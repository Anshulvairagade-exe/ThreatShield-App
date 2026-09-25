"""
Deep MLP Reconstruction Autoencoder.
Trains an unsupervised neural bottleneck manifold to compress and reconstruct normal enterprise behavior.
Deviations in feature combinations yield high reconstruction error, exposing zero-day threats.
"""

from typing import Tuple
import numpy as np
from sklearn.neural_network import MLPRegressor

class ReconstructionAutoencoder:
    """
    Unsupervised Deep Autoencoder for behavioral anomaly detection.
    Compresses input dimension D -> 16 -> 8 (bottleneck) -> 16 -> D.
    """

    def __init__(self, input_dim: int = 24, latent_dim: int = 8, random_state: int = 42):
        self.input_dim = input_dim
        self.latent_dim = latent_dim
        self.random_state = random_state
        self.model = MLPRegressor(
            hidden_layer_sizes=(16, self.latent_dim, 16),
            activation="relu",
            solver="adam",
            alpha=1e-4,  # L2 regularization
            batch_size=64,
            learning_rate="adaptive",
            learning_rate_init=0.005,
            max_iter=300,
            shuffle=True,
            random_state=self.random_state,
            early_stopping=True,
            validation_fraction=0.1,
            n_iter_no_change=15
        )
        self.is_fitted = False

    def fit(self, X: np.ndarray):
        """Trains autoencoder to reconstruct normal baseline data (X -> X)."""
        self.model.fit(X, X)
        self.is_fitted = True

    def reconstruct(self, X: np.ndarray) -> np.ndarray:
        """Outputs reconstructed feature vectors X_hat."""
        if not self.is_fitted:
            raise ValueError("Autoencoder is not fitted.")
        return self.model.predict(X)

    def compute_reconstruction_error(self, X: np.ndarray) -> np.ndarray:
        """
        Computes Mean Squared Error (MSE) per sample:
        MSE = (1/D) * sum((X - X_hat)^2)
        """
        X_hat = self.reconstruct(X)
        sq_err = np.square(X - X_hat)
        mse = np.mean(sq_err, axis=1)
        return mse

    def compute_feature_attribution(self, X: np.ndarray) -> Tuple[np.ndarray, np.ndarray]:
        """
        Returns:
            sample_mse: 1D array of sample reconstruction errors
            feature_sq_err: 2D array of per-feature squared errors (N, D)
        """
        X_hat = self.reconstruct(X)
        feature_sq_err = np.square(X - X_hat)
        sample_mse = np.mean(feature_sq_err, axis=1)
        return sample_mse, feature_sq_err
