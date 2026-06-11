"""
train_gnn.py
─────────────
Training script for the Attack Path GAT model.

Features:
  • Stratified train/val/test split (70/15/15)
  • Early stopping with patience
  • Learning rate scheduling (StepLR)
  • Saves best checkpoint with full metadata
  • Prints classification report (precision, recall, F1, ROC-AUC)

Usage:
    python gnn/train_gnn.py
    python gnn/train_gnn.py --epochs 200 --hidden 64 --heads 8 --lr 0.001
"""

import argparse
import sys
import time
from pathlib import Path

import torch
import torch.nn.functional as F
from sklearn.metrics import (
    accuracy_score,
    classification_report,
    roc_auc_score,
)
from torch_geometric.loader import DataLoader

sys.path.insert(0, str(Path(__file__).parent.parent))
from config.settings import GNN_CONFIG, MODEL_PATH, DATASET_PATH
from gnn.gnn_model import AttackPathGAT


# ── Data loading ──────────────────────────────────────────────────────────────

def load_and_split(
    dataset_path: Path,
    train_ratio: float = 0.70,
    val_ratio: float = 0.15,
    seed: int = 42,
):
    """Load PyG dataset and split into train/val/test sets."""
    if not dataset_path.exists():
        raise FileNotFoundError(
            f"Dataset not found at {dataset_path}.\n"
            f"Run: python data/generate_synthetic_data.py"
        )

    dataset = torch.load(dataset_path)
    torch.manual_seed(seed)
    perm = torch.randperm(len(dataset))
    dataset = [dataset[i] for i in perm]

    n = len(dataset)
    n_train = int(n * train_ratio)
    n_val = int(n * val_ratio)

    train_data = dataset[:n_train]
    val_data = dataset[n_train: n_train + n_val]
    test_data = dataset[n_train + n_val:]

    print(f"Dataset split: {len(train_data)} train / "
          f"{len(val_data)} val / {len(test_data)} test")
    return train_data, val_data, test_data


# ── Training loop ─────────────────────────────────────────────────────────────

def train_one_epoch(model, loader, optimizer, device):
    model.train()
    total_loss = 0.0
    for batch in loader:
        batch = batch.to(device)
        optimizer.zero_grad()
        logits = model(batch.x, batch.edge_index, batch.batch, batch.edge_attr)
        loss = F.binary_cross_entropy_with_logits(logits, batch.y)
        loss.backward()
        torch.nn.utils.clip_grad_norm_(model.parameters(), max_norm=1.0)
        optimizer.step()
        total_loss += loss.item() * batch.num_graphs
    return total_loss / len(loader.dataset)


@torch.no_grad()
def evaluate(model, loader, device):
    model.eval()
    preds, probs, labels = [], [], []
    total_loss = 0.0
    for batch in loader:
        batch = batch.to(device)
        logits = model(batch.x, batch.edge_index, batch.batch, batch.edge_attr)
        loss = F.binary_cross_entropy_with_logits(logits, batch.y)
        total_loss += loss.item() * batch.num_graphs
        p = torch.sigmoid(logits)
        probs.extend(p.cpu().tolist())
        preds.extend((p > 0.5).long().cpu().tolist())
        labels.extend(batch.y.long().cpu().tolist())

    avg_loss = total_loss / len(loader.dataset)
    acc = accuracy_score(labels, preds)
    try:
        auc = roc_auc_score(labels, probs)
    except ValueError:
        auc = 0.5
    return avg_loss, acc, auc, preds, probs, labels


# ── Main ──────────────────────────────────────────────────────────────────────

def train(args):
    device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
    print(f"Device: {device}")

    train_data, val_data, test_data = load_and_split(
        DATASET_PATH, seed=args.seed
    )

    train_loader = DataLoader(train_data, batch_size=args.batch_size, shuffle=True)
    val_loader   = DataLoader(val_data,   batch_size=args.batch_size)
    test_loader  = DataLoader(test_data,  batch_size=args.batch_size)

    in_channels = train_data[0].x.shape[1]
    model = AttackPathGAT(
        in_channels=in_channels,
        hidden_channels=args.hidden,
        heads=args.heads,
        dropout=args.dropout,
    ).to(device)

    print(f"Model parameters: {model.count_parameters():,}")

    optimizer = torch.optim.Adam(
        model.parameters(),
        lr=args.lr,
        weight_decay=args.weight_decay,
    )
    scheduler = torch.optim.lr_scheduler.StepLR(
        optimizer, step_size=50, gamma=0.5
    )

    best_val_auc = 0.0
    patience_counter = 0
    best_state = None

    print(f"\n{'Epoch':>6} | {'Train Loss':>10} | {'Val Loss':>9} | "
          f"{'Val Acc':>8} | {'Val AUC':>8} | {'LR':>8}")
    print("─" * 65)

    t_start = time.time()
    for epoch in range(1, args.epochs + 1):
        train_loss = train_one_epoch(model, train_loader, optimizer, device)
        val_loss, val_acc, val_auc, _, _, _ = evaluate(model, val_loader, device)
        scheduler.step()

        if val_auc > best_val_auc:
            best_val_auc = val_auc
            patience_counter = 0
            best_state = {
                "epoch": epoch,
                "model_state_dict": {k: v.clone() for k, v in model.state_dict().items()},
                "val_auc": val_auc,
                "val_acc": val_acc,
                "config": {
                    "in_channels": in_channels,
                    "hidden_channels": args.hidden,
                    "heads": args.heads,
                    "dropout": args.dropout,
                },
            }
        else:
            patience_counter += 1

        if epoch % 10 == 0 or epoch == 1:
            lr = optimizer.param_groups[0]["lr"]
            print(f"{epoch:>6} | {train_loss:>10.4f} | {val_loss:>9.4f} | "
                  f"{val_acc:>7.1%} | {val_auc:>7.3f} | {lr:>8.6f}")

        if patience_counter >= args.patience:
            print(f"\nEarly stopping at epoch {epoch} "
                  f"(no improvement for {args.patience} epochs)")
            break

    elapsed = time.time() - t_start
    print(f"\nTraining complete in {elapsed:.1f}s")

    # Save best model
    if best_state:
        torch.save(best_state, MODEL_PATH)
        print(f"Best model saved → {MODEL_PATH}  "
              f"(epoch {best_state['epoch']}, AUC={best_val_auc:.3f})")

        # Load best for final test evaluation
        model.load_state_dict(best_state["model_state_dict"])

    _, test_acc, test_auc, preds, probs, labels = evaluate(
        model, test_loader, device
    )

    print(f"\n{'─' * 50}")
    print(f"Test Accuracy : {test_acc:.1%}")
    print(f"Test ROC-AUC  : {test_auc:.3f}")
    print(f"\nClassification Report:")
    print(classification_report(
        labels, preds, target_names=["Benign", "Attack"], digits=3
    ))


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Train the Attack Path GAT model")
    parser.add_argument("--epochs",       type=int,   default=GNN_CONFIG.epochs)
    parser.add_argument("--hidden",       type=int,   default=GNN_CONFIG.hidden_channels)
    parser.add_argument("--heads",        type=int,   default=GNN_CONFIG.attention_heads)
    parser.add_argument("--lr",           type=float, default=GNN_CONFIG.learning_rate)
    parser.add_argument("--weight-decay", type=float, default=GNN_CONFIG.weight_decay)
    parser.add_argument("--dropout",      type=float, default=GNN_CONFIG.dropout)
    parser.add_argument("--batch-size",   type=int,   default=GNN_CONFIG.batch_size)
    parser.add_argument("--patience",     type=int,   default=GNN_CONFIG.early_stopping_patience)
    parser.add_argument("--seed",         type=int,   default=42)
    args = parser.parse_args()
    train(args)
