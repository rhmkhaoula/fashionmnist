import torch
import torch.nn as nn
import torch.optim as optim
from torchvision import datasets, transforms
from torch.utils.data import DataLoader
import torch.nn.functional as F
import numpy as np
import matplotlib.pyplot as plt
import pandas as pd
import time
from datetime import datetime
import os
import json
import copy
import hashlib
from collections import defaultdict
import random
import simpy

# Fixer les graines pour la reproductibilité
random.seed(42)
np.random.seed(42)
torch.manual_seed(42)

# ================================
# TRUSTED EXECUTION ENVIRONMENT (TEE) SIMULATION
# ================================

class TEEManager:
    """Simulation d'un Environnement d'Exécution de Confiance (TEE)"""
    
    def __init__(self, uav_id, memory_limit=512*1024*1024):
        self.uav_id = uav_id
        self.memory_limit = memory_limit
        self.secure_memory = {}
        self.is_compromised = False
        self.access_log = []
        self.encryption_key = self._generate_tee_key()
        
        print(f"   🔒 UAV-{uav_id}: TEE initialisé (Mémoire: {memory_limit//1024//1024}MB)")
    
    def _generate_tee_key(self):
        """Génère une clé cryptographique unique pour ce TEE"""
        return hashlib.sha256(f"TEE_KEY_{self.uav_id}_{random.randint(0,999999)}".encode()).hexdigest()
    
    def secure_context(self):
        """Context manager pour l'exécution sécurisée dans TEE"""
        return TEESecureContext(self)
    
    def secure_store(self, key, data):
        """Stockage sécurisé dans la mémoire TEE"""
        if not self.is_compromised:
            encrypted_data = self._encrypt_data(data)
            self.secure_memory[key] = encrypted_data
            self.access_log.append(f"STORE_{key}_{datetime.now()}")
            return True
        return False
    
    def secure_retrieve(self, key):
        """Récupération sécurisée depuis la mémoire TEE"""
        if not self.is_compromised and key in self.secure_memory:
            encrypted_data = self.secure_memory[key]
            data = self._decrypt_data(encrypted_data)
            self.access_log.append(f"RETRIEVE_{key}_{datetime.now()}")
            return data
        return None
    
    def _encrypt_data(self, data):
        """Simulation de chiffrement des données dans TEE"""
        return f"ENCRYPTED_{self.encryption_key[:8]}_{hash(str(data))}"
    
    def _decrypt_data(self, encrypted_data):
        """Simulation de déchiffrement des données dans TEE"""
        if encrypted_data.startswith(f"ENCRYPTED_{self.encryption_key[:8]}"):
            return "DECRYPTED_DATA"
        return None
    
    def get_security_status(self):
        """Retourne le statut de sécurité du TEE"""
        return {
            'compromised': self.is_compromised,
            'memory_usage': len(self.secure_memory),
            'access_count': len(self.access_log),
            'tee_id': self.uav_id
        }

class TEESecureContext:
    """Context manager pour l'exécution sécurisée"""
    
    def __init__(self, tee_manager):
        self.tee = tee_manager
    
    def __enter__(self):
        if self.tee.is_compromised:
            raise SecurityException(f"TEE compromis pour UAV-{self.tee.uav_id}")
        return self.tee
    
    def __exit__(self, exc_type, exc_val, exc_tb):
        pass

class SecurityException(Exception):
    """Exception levée en cas de violation de sécurité TEE"""
    pass

# ================================
# DÉTECTION DE MENACES LOCALE
# ================================

class LocalThreatDetector:
    """Détecteur de menaces local - AUCUNE communication supplémentaire"""
    
    def __init__(self, uav_id):
        self.uav_id = uav_id
        self.baseline_metrics = {}
        self.suspicious_peers = set()
        self.threat_history = []
        self.byzantine_threshold = 3.0
        
    def analyze_peer_updates(self, peer_weights, peer_ids):
        """Analyse locale des mises à jour reçues - PAS de communication"""
        threats_detected = []
        
        if not peer_weights:
            return threats_detected
        
        # 1. Détection d'attaques Byzantine
        byzantine_threats = self._detect_byzantine_attacks(peer_weights, peer_ids)
        threats_detected.extend(byzantine_threats)
        
        # 2. Détection d'attaques Sybil
        sybil_threats = self._detect_sybil_attacks(peer_weights, peer_ids)
        threats_detected.extend(sybil_threats)
        
        # 3. Détection d'anomalies dans les tailles
        size_threats = self._detect_size_anomalies(peer_weights, peer_ids)
        threats_detected.extend(size_threats)
        
        if threats_detected:
            self.threat_history.append({
                'timestamp': datetime.now(),
                'threats': threats_detected,
                'total_peers': len(peer_weights)
            })
        
        return threats_detected
    
    def _detect_byzantine_attacks(self, peer_weights, peer_ids):
        """Détection d'attaques Byzantine par analyse des gradients"""
        threats = []
        
        if len(peer_weights) < 2:
            return threats
        
        # Calculer les similarités entre modèles
        similarities = []
        for i, weights_i in enumerate(peer_weights):
            for j, weights_j in enumerate(peer_weights[i+1:], i+1):
                sim = self._calculate_model_similarity(weights_i, weights_j)
                similarities.append((peer_ids[i], peer_ids[j], sim))
        
        # Identifier les outliers
        if similarities:
            sim_values = [sim[2] for sim in similarities]
            mean_sim = np.mean(sim_values)
            std_sim = np.std(sim_values)
            
            for peer_id, weights in zip(peer_ids, peer_weights):
                peer_similarities = [sim[2] for sim in similarities 
                                   if sim[0] == peer_id or sim[1] == peer_id]
                
                if peer_similarities:
                    avg_peer_sim = np.mean(peer_similarities)
                    if avg_peer_sim < (mean_sim - self.byzantine_threshold * std_sim):
                        threats.append({
                            'type': 'Byzantine',
                            'peer_id': peer_id,
                            'severity': 'HIGH',
                            'similarity_score': avg_peer_sim
                        })
                        self.suspicious_peers.add(peer_id)
        
        return threats
    
    def _detect_sybil_attacks(self, peer_weights, peer_ids):
        """Détection d'attaques Sybil par analyse des patterns"""
        threats = []
        
        for i, weights_i in enumerate(peer_weights):
            for j, weights_j in enumerate(peer_weights[i+1:], i+1):
                similarity = self._calculate_model_similarity(weights_i, weights_j)
                
                if similarity > 0.99:
                    threats.append({
                        'type': 'Sybil',
                        'peer_ids': [peer_ids[i], peer_ids[j]],
                        'severity': 'MEDIUM',
                        'similarity': similarity
                    })
        
        return threats
    
    def _detect_size_anomalies(self, peer_weights, peer_ids):
        """Détection d'anomalies dans les tailles de modèles"""
        threats = []
        
        model_sizes = []
        for weights in peer_weights:
            size = sum(w.numel() for w in weights.values())
            model_sizes.append(size)
        
        if len(model_sizes) > 1:
            mean_size = np.mean(model_sizes)
            std_size = np.std(model_sizes)
            
            for i, (peer_id, size) in enumerate(zip(peer_ids, model_sizes)):
                if abs(size - mean_size) > 2 * std_size:
                    threats.append({
                        'type': 'Size_Anomaly',
                        'peer_id': peer_id,
                        'severity': 'LOW',
                        'size_deviation': abs(size - mean_size) / mean_size
                    })
        
        return threats
    
    def _calculate_model_similarity(self, weights1, weights2):
        """Calcule la similarité entre deux modèles"""
        try:
            total_similarity = 0.0
            total_params = 0
            
            common_keys = set(weights1.keys()) & set(weights2.keys())
            
            for key in common_keys:
                w1 = weights1[key].flatten()
                w2 = weights2[key].flatten()
                
                if w1.shape == w2.shape:
                    cos_sim = torch.nn.functional.cosine_similarity(
                        w1.unsqueeze(0), w2.unsqueeze(0)
                    ).item()
                    
                    param_count = w1.numel()
                    total_similarity += cos_sim * param_count
                    total_params += param_count
            
            return total_similarity / total_params if total_params > 0 else 0.0
            
        except Exception:
            return 0.0
    
    def filter_suspicious_updates(self, peer_weights, peer_ids, threats):
        """Filtre les mises à jour suspectes sans communication"""
        clean_weights = []
        clean_ids = []
        
        suspect_ids = set()
        for threat in threats:
            if threat['severity'] in ['HIGH', 'CRITICAL']:
                if 'peer_id' in threat:
                    suspect_ids.add(threat['peer_id'])
                elif 'peer_ids' in threat:
                    suspect_ids.update(threat['peer_ids'])
        
        for weights, peer_id in zip(peer_weights, peer_ids):
            if peer_id not in suspect_ids:
                clean_weights.append(weights)
                clean_ids.append(peer_id)
        
        if suspect_ids:
            print(f"   🛡️ UAV-{self.uav_id}: {len(suspect_ids)} UAV suspects filtrés: {list(suspect_ids)}")
        
        return clean_weights, clean_ids

# ================================
# MODÈLES CNN - ARCHITECTURE DE test_fin.py AVEC SUPPORT GREEDY
# ================================

class CNNModelMNIST(nn.Module):
    """Modèle CNN MNIST - Simple avec support Greedy"""
    
    def __init__(self, enable_greedy=False):
        super(CNNModelMNIST, self).__init__()
        
        self.enable_greedy = enable_greedy
        self.current_fc_depth = 1
        self.max_fc_layers = 3
        
        # Architecture simple pour MNIST
        self.conv1 = nn.Conv2d(1, 32, kernel_size=5, padding=2)
        self.conv2 = nn.Conv2d(32, 64, kernel_size=5, padding=2)
        self.pool = nn.MaxPool2d(2, 2)
        self.dropout = nn.Dropout(0.25)
        
        # Couches FC simples
        self.fc1 = nn.Linear(64 * 7 * 7, 256)
        self.fc2 = nn.Linear(256, 128)
        self.fc3 = nn.Linear(128, 10)
        
        # Couches de sortie pour Greedy
        if self.enable_greedy:
            self.output_layers = nn.ModuleDict({
                '1': nn.Linear(256, 10),
                '2': nn.Linear(128, 10),
                '3': nn.Linear(10, 10)
            })
            self._freeze_unused_layers()

    def _freeze_unused_layers(self):
        """Gèle les couches non utilisées en mode Greedy"""
        if not self.enable_greedy:
            return
            
        layers = [self.fc1, self.fc2, self.fc3]
        for i, layer in enumerate(layers):
            if i >= self.current_fc_depth:
                for param in layer.parameters():
                    param.requires_grad = False
            else:
                for param in layer.parameters():
                    param.requires_grad = True
        
        if hasattr(self, 'output_layers'):
            for key, layer in self.output_layers.items():
                if key == str(self.current_fc_depth):
                    for param in layer.parameters():
                        param.requires_grad = True
                else:
                    for param in layer.parameters():
                        param.requires_grad = False

    def add_greedy_layer(self):
        """Ajoute une couche FC (Greedy Layer-Wise)"""
        if not self.enable_greedy or self.current_fc_depth >= self.max_fc_layers:
            return False
            
        print(f"   🧠 Ajout couche FC #{self.current_fc_depth + 1} (Greedy)")
        
        layers = [self.fc1, self.fc2, self.fc3]
        for i in range(self.current_fc_depth):
            for param in layers[i].parameters():
                param.requires_grad = False
        
        self.current_fc_depth += 1
        self._freeze_unused_layers()
        
        return True

    def forward(self, x):
        # Forward simple pour MNIST
        x = F.relu(self.conv1(x))
        x = self.pool(x)
        x = F.relu(self.conv2(x))
        x = self.pool(x)
        x = self.dropout(x)
        
        x = x.view(-1, 64 * 7 * 7)
        
        if self.enable_greedy:
            # Mode Greedy: utiliser seulement les couches actives
            x = F.relu(self.fc1(x))
            if self.current_fc_depth == 1:
                return self.output_layers['1'](x)
            
            x = F.relu(self.fc2(x))
            if self.current_fc_depth == 2:
                return self.output_layers['2'](x)
                
            x = self.fc3(x)
            return x
        else:
            # Mode standard
            x = F.relu(self.fc1(x))
            x = F.relu(self.fc2(x))
            x = self.fc3(x)
            return x

    def get_greedy_status(self):
        """Retourne le statut du Greedy"""
        return {
            'enabled': self.enable_greedy,
            'current_depth': self.current_fc_depth,
            'max_depth': self.max_fc_layers,
            'can_add_layer': self.current_fc_depth < self.max_fc_layers
        }

class CNNModelCIFAR10(nn.Module):
    """🔧 Modèle CNN CIFAR-10 - Architecture EXACTE de test_fin.py avec support Greedy ajouté"""
    
    def __init__(self, enable_greedy=False):
        super(CNNModelCIFAR10, self).__init__()
        
        # Support Greedy Layer-Wise
        self.enable_greedy = enable_greedy
        self.current_fc_depth = 1
        self.max_fc_layers = 3
        
        # 🔧 ARCHITECTURE EXACTE DE test_fin.py
        # Premier bloc convolutionnel
        self.conv1 = nn.Conv2d(3, 64, kernel_size=3, padding=1)
        self.bn1 = nn.BatchNorm2d(64)
        
        # Deuxième bloc convolutionnel
        self.conv2 = nn.Conv2d(64, 128, kernel_size=3, padding=1)
        self.bn2 = nn.BatchNorm2d(128)
        
        # Troisième bloc convolutionnel
        self.conv3 = nn.Conv2d(128, 256, kernel_size=3, padding=1)
        self.bn3 = nn.BatchNorm2d(256)
        
        # Quatrième bloc convolutionnel
        self.conv4 = nn.Conv2d(256, 512, kernel_size=3, padding=1)
        self.bn4 = nn.BatchNorm2d(512)
        
        # Pooling et dropout - EXACTEMENT comme test_fin.py
        self.pool = nn.MaxPool2d(2, 2)
        self.dropout = nn.Dropout(0.3)
        self.dropout_fc = nn.Dropout(0.5)
        
        # Couches fully connected - EXACTEMENT comme test_fin.py
        self.fc1 = nn.Linear(512 * 2 * 2, 1024)
        self.bn_fc1 = nn.BatchNorm1d(1024)
        self.fc2 = nn.Linear(1024, 512)
        self.bn_fc2 = nn.BatchNorm1d(512)
        self.fc3 = nn.Linear(512, 10)
        
        # Couches de sortie pour Greedy (ajout pour test_dfl_tee.py)
        if self.enable_greedy:
            self.output_layers = nn.ModuleDict({
                '1': nn.Linear(1024, 10),
                '2': nn.Linear(512, 10),
                '3': nn.Linear(10, 10)
            })
            self._freeze_unused_layers()

    def _freeze_unused_layers(self):
        """Gèle les couches non utilisées en mode Greedy"""
        if not self.enable_greedy:
            return
            
        fc_layers = [
            (self.fc1, self.bn_fc1),
            (self.fc2, self.bn_fc2), 
            (self.fc3, None)
        ]
        
        for i, (fc, bn) in enumerate(fc_layers):
            if i >= self.current_fc_depth:
                for param in fc.parameters():
                    param.requires_grad = False
                if bn is not None:
                    for param in bn.parameters():
                        param.requires_grad = False
            else:
                for param in fc.parameters():
                    param.requires_grad = True
                if bn is not None:
                    for param in bn.parameters():
                        param.requires_grad = True
        
        # Gérer les couches de sortie Greedy
        if hasattr(self, 'output_layers'):
            for key, layer in self.output_layers.items():
                if key == str(self.current_fc_depth):
                    for param in layer.parameters():
                        param.requires_grad = True
                else:
                    for param in layer.parameters():
                        param.requires_grad = False

    def add_greedy_layer(self):
        """Ajoute une couche FC (Greedy Layer-Wise)"""
        if not self.enable_greedy or self.current_fc_depth >= self.max_fc_layers:
            return False
            
        print(f"   🧠 Ajout couche FC #{self.current_fc_depth + 1} (Greedy CIFAR-10 de test_fin.py)")
        
        fc_layers = [
            (self.fc1, self.bn_fc1),
            (self.fc2, self.bn_fc2), 
            (self.fc3, None)
        ]
        
        # Geler les couches précédentes
        for i in range(self.current_fc_depth):
            fc, bn = fc_layers[i]
            for param in fc.parameters():
                param.requires_grad = False
            if bn is not None:
                for param in bn.parameters():
                    param.requires_grad = False
        
        self.current_fc_depth += 1
        self._freeze_unused_layers()
        
        return True

    def forward(self, x):
        # 🔧 FORWARD EXACTEMENT COMME test_fin.py
        # Premier bloc: Conv + BN + ReLU + Pool
        x = self.pool(F.relu(self.bn1(self.conv1(x))))
        
        # Deuxième bloc: Conv + BN + ReLU + Pool
        x = self.pool(F.relu(self.bn2(self.conv2(x))))
        
        # Troisième bloc: Conv + BN + ReLU + Pool
        x = self.pool(F.relu(self.bn3(self.conv3(x))))
        
        # Quatrième bloc: Conv + BN + ReLU + Pool
        x = self.pool(F.relu(self.bn4(self.conv4(x))))
        
        # Dropout après les convolutions
        x = self.dropout(x)
        
        # Aplatissement pour les couches FC
        x = x.view(-1, 512 * 2 * 2)
        
        if self.enable_greedy:
            # Mode Greedy: utiliser seulement les couches actives
            if self.current_fc_depth >= 1:
                x = F.relu(self.bn_fc1(self.fc1(x)))
                x = self.dropout_fc(x)
                if self.current_fc_depth == 1:
                    return self.output_layers['1'](x)
            
            if self.current_fc_depth >= 2:
                x = F.relu(self.bn_fc2(self.fc2(x)))
                x = self.dropout_fc(x)
                if self.current_fc_depth == 2:
                    return self.output_layers['2'](x)
                    
            if self.current_fc_depth >= 3:
                x = self.fc3(x)
                return x
        else:
            # Mode standard: EXACTEMENT comme test_fin.py
            # Première couche FC avec BN
            x = F.relu(self.bn_fc1(self.fc1(x)))
            x = self.dropout_fc(x)
            
            # Deuxième couche FC avec BN
            x = F.relu(self.bn_fc2(self.fc2(x)))
            x = self.dropout_fc(x)
            
            # Couche de sortie
            x = self.fc3(x)
            
            return x

    def get_greedy_status(self):
        """Retourne le statut du Greedy"""
        return {
            'enabled': self.enable_greedy,
            'current_depth': self.current_fc_depth,
            'max_depth': self.max_fc_layers,
            'can_add_layer': self.current_fc_depth < self.max_fc_layers
        }

# ================================
# FONCTIONS UTILITAIRES POSITIONS & COMMUNICATION
# ================================

def euclidean_distance(pos1, pos2):
    """Calcule la distance euclidienne entre deux positions"""
    return ((pos1[0] - pos2[0]) ** 2 + (pos1[1] - pos2[1]) ** 2) ** 0.5

def get_comm_delay(uav_id, peer_id, uav_positions):
    """Calcule le délai de communication basé sur la distance"""
    distance = euclidean_distance(uav_positions[uav_id], uav_positions[peer_id])
    base_delay = 1.0
    delay = base_delay + 0.05 * distance
    return delay

def create_uav_positions(num_uavs, area_size=100, groups=None):
    """Génération positions avec clusters géographiquement proches"""
    positions = []
    
    if groups is None:
        return [(random.uniform(0, area_size), random.uniform(0, area_size)) for _ in range(num_uavs)]
    
    # Générer des centres de clusters dans la zone
    num_clusters = len(groups)
    cluster_centers = []
    
    # Distribuer les centres de clusters dans la zone
    for i in range(num_clusters):
        if num_clusters == 1:
            center_x = area_size / 2
            center_y = area_size / 2
        elif num_clusters == 2:
            center_x = (i + 1) * area_size / 3
            center_y = area_size / 2
        elif num_clusters == 3:
            # Triangle équilatéral
            angle = i * 2 * 3.14159 / 3
            radius = area_size / 3
            center_x = area_size / 2 + radius * np.cos(angle)
            center_y = area_size / 2 + radius * np.sin(angle)
        else:
            # Grille pour plus de clusters
            cols = int(np.ceil(np.sqrt(num_clusters)))
            row = i // cols
            col = i % cols
            center_x = (col + 1) * area_size / (cols + 1)
            center_y = (row + 1) * area_size / (cols + 1)
        
        cluster_centers.append((center_x, center_y))
    
    # Créer positions pour chaque cluster
    for cluster_idx, group in enumerate(groups):
        center = cluster_centers[cluster_idx]
        cluster_radius = min(20, area_size / (2 * len(groups)))
        
        for uav_id in group:
            # Position aléatoire autour du centre du cluster
            angle = random.uniform(0, 2 * 3.14159)
            distance = random.uniform(0, cluster_radius)
            
            x = center[0] + distance * np.cos(angle)
            y = center[1] + distance * np.sin(angle)
            
            # Vérifier les limites de la zone
            x = max(5, min(area_size - 5, x))
            y = max(5, min(area_size - 5, y))
            
            positions.append((x, y))
    
    return positions

def generate_network_topology_image(positions, groups, filename=None):
    """Générer une image PNG de la topologie avec liens de communication"""
    
    if filename is None:
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"topology/network_topology_{timestamp}.png"
    
    os.makedirs('topology', exist_ok=True)
    
    plt.figure(figsize=(12, 10))
    
    colors = ['red', 'blue', 'green', 'orange', 'purple', 'brown', 'pink', 'gray', 'olive', 'cyan']
    communication_range = 30.0
    
    # Liens intra-cluster
    for cluster_idx, group in enumerate(groups):
        color = colors[cluster_idx % len(colors)]
        for i, uav_id1 in enumerate(group):
            for uav_id2 in group[i+1:]:
                pos1 = positions[uav_id1]
                pos2 = positions[uav_id2]
                distance = euclidean_distance(pos1, pos2)
                
                if distance <= communication_range:
                    plt.plot([pos1[0], pos2[0]], [pos1[1], pos2[1]], 
                            color=color, linestyle='-', linewidth=1.5, alpha=0.7)
    
    # Centres de clusters
    cluster_centers = []
    for cluster_idx, group in enumerate(groups):
        cluster_positions = [positions[uav_id] for uav_id in group]
        center_x = sum(pos[0] for pos in cluster_positions) / len(cluster_positions)
        center_y = sum(pos[1] for pos in cluster_positions) / len(cluster_positions)
        cluster_centers.append((center_x, center_y))
        
        plt.scatter(center_x, center_y, c='black', s=200, marker='X', 
                   edgecolors='white', linewidth=2, alpha=0.8, zorder=10)
        plt.annotate(f'Centre C{cluster_idx}', (center_x, center_y), 
                    xytext=(10, 10), textcoords='offset points',
                    fontsize=10, fontweight='bold', color='black')
    
    # Liens inter-cluster
    for i in range(len(cluster_centers)):
        for j in range(i+1, len(cluster_centers)):
            center1 = cluster_centers[i]
            center2 = cluster_centers[j]
            plt.plot([center1[0], center2[0]], [center1[1], center2[1]], 
                    color='black', linestyle='--', linewidth=2, alpha=0.6)
    
    # Nœuds UAV par cluster
    for cluster_idx, group in enumerate(groups):
        cluster_positions = [positions[uav_id] for uav_id in group]
        x_coords = [pos[0] for pos in cluster_positions]
        y_coords = [pos[1] for pos in cluster_positions]
        
        color = colors[cluster_idx % len(colors)]
        
        plt.scatter(x_coords, y_coords, c=color, s=150, alpha=0.9, 
                   label=f'Cluster {cluster_idx}', edgecolors='black', linewidth=2, zorder=5)
        
        for uav_id, pos in zip(group, cluster_positions):
            plt.annotate(f'UAV-{uav_id}', (pos[0], pos[1]), 
                        xytext=(5, 5), textcoords='offset points',
                        fontsize=9, fontweight='bold', color='black',
                        bbox=dict(boxstyle='round,pad=0.3', facecolor='white', alpha=0.8))
    
    # Cercles de portée de communication
    for uav_id, pos in enumerate(positions):
        circle = plt.Circle(pos, communication_range, fill=False, 
                          linestyle=':', alpha=0.2, color='gray', linewidth=1)
        plt.gca().add_patch(circle)
    
    plt.xlabel('Coordonnée X (km)', fontsize=14)
    plt.ylabel('Coordonnée Y (km)', fontsize=14)
    # 🔧 TITRE MODIFIÉ pour refléter l'utilisation du modèle de test_fin.py
    plt.title('Topologie Sécurisée TEE + Coefficient Alpha\nArchitecture CIFAR-10 de test_fin.py + Contrôle d\'Influence', 
              fontsize=16, fontweight='bold')
    plt.legend(bbox_to_anchor=(1.05, 1), loc='upper left', fontsize=12)
    plt.grid(True, alpha=0.3)
    plt.axis('equal')
    
    plt.xlim(-5, 105)
    plt.ylim(-5, 75)
    
    info_text = f"""Réseau UAV Sécurisé + Alpha:
• {len(positions)} drones avec TEE
• {len(groups)} clusters
• Zone: 100x100 km
• Portée comm: {communication_range} km
• Sécurité: TEE + Détection menaces
• Coefficient Alpha: Contrôle d'influence
• Modèle CIFAR-10: Architecture de test_fin.py
• Simulation: SimPy Environment
• Liens: — Intra-cluster, -- Inter-cluster"""
    
    plt.text(0.02, 0.98, info_text, transform=plt.gca().transAxes, 
             fontsize=10, verticalalignment='top',
             bbox=dict(boxstyle='round', facecolor='lightblue', alpha=0.8))
    
    plt.tight_layout()
    plt.savefig(filename, dpi=300, bbox_inches='tight')
    plt.close()
    
    print(f"🗺️ Topologie sécurisée avec architecture test_fin.py sauvegardée: {filename}")
    return filename

# ================================
# FONCTIONS DATASET ET ÉVALUATION
# ================================

def partition_dataset(num_uavs, iid=True, dataset_name="MNIST"):
    """Partitionner le dataset selon IID ou Non-IID"""
    print(f"📦 Partitionnement du dataset {dataset_name} ({'IID' if iid else 'Non-IID'})...")
    
    if dataset_name == "MNIST":
        transform = transforms.Compose([transforms.ToTensor()])
        full_dataset = datasets.MNIST(root='./data', train=True, download=True, transform=transform)
    elif dataset_name == "CIFAR-10":
        transform = transforms.Compose([transforms.ToTensor()])
        full_dataset = datasets.CIFAR10(root='./data', train=True, download=True, transform=transform)
    
    if iid:
        data_per_uav = len(full_dataset) // num_uavs
        indices = np.random.permutation(len(full_dataset))
        partitions = []
        
        for i in range(num_uavs):
            start = i * data_per_uav
            end = (i + 1) * data_per_uav if i < num_uavs - 1 else len(full_dataset)
            uav_indices = indices[start:end]
            subset = torch.utils.data.Subset(full_dataset, indices)
            partitions.append(subset)
            
        print(f"   ✅ Distribution IID : {data_per_uav} échantillons par UAV")
        
    else:
        targets = np.array(full_dataset.targets)
        sorted_indices = np.argsort(targets)
        
        num_classes = 10
        classes_per_uav = max(1, num_classes // num_uavs)
        
        partitions = []
        for i in range(num_uavs):
            start_class = (i * classes_per_uav) % num_classes
            end_class = ((i + 1) * classes_per_uav) % num_classes
            
            if end_class <= start_class:
                end_class = start_class + 1
            
            uav_indices = []
            for class_id in range(start_class, min(end_class + 1, num_classes)):
                class_indices = sorted_indices[targets[sorted_indices] == class_id]
                samples_per_class = len(class_indices) // (num_uavs // classes_per_uav + 1)
                uav_indices.extend(class_indices[:samples_per_class])
            
            subset = torch.utils.data.Subset(full_dataset, uav_indices)
            partitions.append(subset)
            
        print(f"   ✅ Distribution Non-IID : répartition par classes")
    
    return partitions

def load_test_dataset(dataset_name, enable_greedy=False):
    """Charger le dataset de test avec modèle CIFAR-10 de test_fin.py"""
    if dataset_name == "MNIST":
        transform = transforms.Compose([transforms.ToTensor()])
        test_dataset = datasets.MNIST(root='./data', train=False, download=True, transform=transform)
        model_class = lambda: CNNModelMNIST(enable_greedy=enable_greedy)
    else:  # CIFAR-10
        transform = transforms.Compose([transforms.ToTensor()])
        test_dataset = datasets.CIFAR10(root='./data', train=False, download=True, transform=transform)
        # 🔧 UTILISE L'ARCHITECTURE EXACTE DE test_fin.py avec support Greedy
        model_class = lambda: CNNModelCIFAR10(enable_greedy=enable_greedy)
    
    test_loader = DataLoader(test_dataset, batch_size=256, shuffle=False)
    return test_loader, model_class

def evaluate_model(model_instance, test_loader, device='cpu'):
    """Évaluer la performance du modèle"""
    model_instance.eval()
    
    correct = 0
    total = 0
    
    with torch.no_grad():
        for xb, yb in test_loader:
            xb = xb.to(torch.float32).to(device)
            if len(xb.shape) == 3:
                xb = xb.unsqueeze(1)
            yb = yb.to(device)
            
            outputs = model_instance(xb)
            _, predicted = torch.max(outputs.data, 1)
            total += yb.size(0)
            correct += (predicted == yb).sum().item()
    
    return correct / total

# ================================
# FONCTIONS D'AGRÉGATION AVEC COEFFICIENT ALPHA
# ================================

def weighted_fedavg(models_weights, weights_list):
    """Agrégation Weighted FedAvg standard (pour intra-cluster)"""
    if not models_weights:
        return None
        
    total_weight = sum(weights_list)
    if total_weight == 0:
        return None
        
    normalized_weights = [w / total_weight for w in weights_list]
    
    aggregated_weights = {}
    
    for key in models_weights[0].keys():
        aggregated_weights[key] = sum(
            normalized_weights[i] * models_weights[i][key] 
            for i in range(len(models_weights))
        )
    
    return aggregated_weights

def weighted_fedavg_with_alpha(local_model, external_models, external_weights, alpha=0.3):
    """
    Agrégation Weighted FedAvg avec coefficient alpha pour les modèles externes
    
    Args:
        local_model: Poids du modèle local (cluster actuel)
        external_models: Liste des modèles des autres clusters
        external_weights: Liste des poids (tailles) des autres clusters
        alpha: Coefficient de réduction pour les modèles externes (0 < alpha < 1)
    
    Returns:
        Modèle agrégé avec influence réduite des clusters externes
    """
    if not external_models:
        return local_model
    
    # Calculer le poids total des modèles externes
    total_external_weight = sum(external_weights)
    if total_external_weight == 0:
        return local_model
    
    # Normaliser les poids externes
    normalized_external_weights = [w / total_external_weight for w in external_weights]
    
    # Calculer la moyenne pondérée des modèles externes
    external_aggregated = {}
    for key in local_model.keys():
        external_aggregated[key] = sum(
            normalized_external_weights[i] * external_models[i][key]
            for i in range(len(external_models))
        )
    
    # Agrégation finale avec coefficient alpha
    final_model = {}
    for key in local_model.keys():
        # Modèle final = (1-alpha) * modèle_local + alpha * modèles_externes_agrégés
        final_model[key] = (1 - alpha) * local_model[key] + alpha * external_aggregated[key]
    
    return final_model

# ================================
# GESTIONNAIRE DE CLUSTERS
# ================================

class ClusterManager:
    """Gestionnaire des clusters"""
    
    def __init__(self, env, groups, global_results):
        self.env = env
        self.groups = groups
        self.global_results = global_results
        self.cluster_leaders = {}
        
    def elect_cluster_leader(self, cluster_id, round_num):
        """Élire un chef de cluster pour ce round"""
        cluster_uavs = self.groups[cluster_id]
        leader_index = round_num % len(cluster_uavs)
        leader_id = cluster_uavs[leader_index]
        self.cluster_leaders[cluster_id] = leader_id
        
        return leader_id

# ================================
# CLASSE UAV SÉCURISÉE AVEC COEFFICIENT ALPHA
# ================================

class SecureUAV:
    """Classe UAV sécurisée avec modèle CIFAR-10 de test_fin.py et coefficient alpha"""
    
    def __init__(self, env, uav_id, cluster_id, group_ids, dataset, test_loader, model_class, 
                 protocol, positions, config, global_results, cluster_manager, enable_greedy=False):
        self.env = env
        self.id = uav_id
        self.cluster_id = cluster_id
        self.group_ids = group_ids
        self.dataset = dataset
        self.test_loader = test_loader
        self.model_class = model_class
        self.protocol = protocol
        self.positions = positions
        self.config = config
        self.global_results = global_results
        self.cluster_manager = cluster_manager
        self.enable_greedy = enable_greedy
        
        # Coefficient alpha pour inter-cluster (configurable)
        self.alpha_inter_cluster = config.get('alpha_inter_cluster', 0.3)
        
        # Initialiser le TEE
        self.tee = TEEManager(uav_id, memory_limit=512*1024*1024)
        
        # Initialiser le détecteur de menaces local
        self.threat_detector = LocalThreatDetector(uav_id)
        
        # Initialiser le modèle DANS LE TEE
        with self.tee.secure_context():
            self.model = model_class()  # 🔧 UTILISE LE MODÈLE CIFAR-10 DE test_fin.py
            self.tee.secure_store(f"model_{uav_id}", self.model)
        
        # Paramètres Greedy Layer-Wise
        self.greedy_patience = 2
        self.greedy_threshold = 0.01
        self.last_accuracy = 0.0
        self.no_improvement_count = 0
        self.greedy_history = []
        
        # Statistiques
        self.local_losses = []
        self.round_accuracies = []
        self.communication_cost = 0
        self.computational_cost = 0
        self.is_cluster_leader = False
        
        # Statistiques de sécurité
        self.security_stats = {
            'threats_detected': 0,
            'tee_operations': 0,
            'secure_trainings': 0
        }
        
        # Démarrage du processus
        self.env.process(self.secure_federated_learning_process())

    def secure_local_training(self):
        """Entraînement local sécurisé dans TEE avec modèle CIFAR-10 de test_fin.py"""
        print(f"   🔒 UAV-{self.id}: Entraînement {'Greedy' if self.enable_greedy else 'Standard'} sécurisé (CIFAR-10 de test_fin.py)")
        
        with self.tee.secure_context() as tee:
            self.security_stats['secure_trainings'] += 1
            
            self.model.train()
            
            # Optimiseur adapté selon architecture de test_fin.py
            if self.enable_greedy:
                optimizer = optim.SGD(
                    filter(lambda p: p.requires_grad, self.model.parameters()), 
                    lr=0.01, momentum=0.9, weight_decay=1e-4
                )
            else:
                optimizer = optim.SGD(
                    self.model.parameters(), 
                    lr=0.01, momentum=0.9
                )
            
            criterion = nn.CrossEntropyLoss()
            loader = DataLoader(self.dataset, batch_size=self.config['batch_size'], shuffle=True)
            
            total_loss = 0.0
            total_batches = 0
            
            for epoch in range(self.config['local_epochs']):
                epoch_loss = 0.0
                epoch_batches = 0
                
                for batch_data, batch_labels in loader:
                    batch_data = batch_data.to(torch.float32)
                    if len(batch_data.shape) == 3:
                        batch_data = batch_data.unsqueeze(1)
                    
                    optimizer.zero_grad()
                    outputs = self.model(batch_data)
                    loss = criterion(outputs, batch_labels)
                    loss.backward()
                    optimizer.step()
                    
                    epoch_loss += loss.item()
                    epoch_batches += 1
                    self.computational_cost += len(batch_data)
                
                avg_epoch_loss = epoch_loss / epoch_batches if epoch_batches > 0 else 0
                total_loss += avg_epoch_loss
                total_batches += 1
                
                # Greedy Logic pour architecture de test_fin.py
                if self.enable_greedy and epoch == self.config['local_epochs'] - 1:
                    current_accuracy = evaluate_model(self.model, self.test_loader)
                    
                    if self._should_add_greedy_layer(current_accuracy):
                        if self.model.add_greedy_layer():
                            self.greedy_history.append({
                                'round': self.global_results.get('current_round', 0),
                                'epoch': epoch,
                                'old_accuracy': self.last_accuracy,
                                'new_depth': self.model.current_fc_depth
                            })
                            print(f"     ⚡🔒 Couche ajoutée dans TEE! Nouvelle profondeur: {self.model.current_fc_depth}")
                            
                            # Réinitialiser l'optimiseur pour les nouveaux paramètres
                            optimizer = optim.SGD(
                                filter(lambda p: p.requires_grad, self.model.parameters()), 
                                lr=0.01, momentum=0.9, weight_decay=1e-4
                            )
                    
                    self.last_accuracy = current_accuracy
            
            tee.secure_store(f"trained_model_{self.id}", self.model.state_dict())
            self.security_stats['tee_operations'] += 1
        
        avg_loss = total_loss / total_batches if total_batches > 0 else 0
        self.local_losses.append(avg_loss)
        
        return avg_loss

    def _should_add_greedy_layer(self, current_accuracy):
        """Détermine s'il faut ajouter une couche Greedy"""
        if not self.enable_greedy:
            return False
            
        improvement = current_accuracy - self.last_accuracy
        
        if improvement < self.greedy_threshold:
            self.no_improvement_count += 1
        else:
            self.no_improvement_count = 0
            
        should_add = (self.no_improvement_count >= self.greedy_patience and 
                     self.model.current_fc_depth < self.model.max_fc_layers)
        
        if should_add:
            self.no_improvement_count = 0
            
        return should_add

    def get_model_weights(self):
        """Récupérer les poids du modèle DEPUIS TEE"""
        with self.tee.secure_context() as tee:
            weights = {k: v.cpu().clone() for k, v in self.model.state_dict().items()}
            tee.secure_store(f"extracted_weights_{self.id}", "extraction_logged")
            self.security_stats['tee_operations'] += 1
            
        return weights

    def set_model_weights(self, weights):
        """Définir les poids du modèle DANS TEE avec compatibilité test_fin.py"""
        with self.tee.secure_context() as tee:
            current_state = self.model.state_dict()
            
            # Compatibilité parfaite avec architecture de test_fin.py
            compatible_weights = {}
            for key, value in weights.items():
                if key in current_state:
                    if current_state[key].shape == value.shape:
                        compatible_weights[key] = value
                    else:
                        # Conserver les poids actuels si incompatible
                        compatible_weights[key] = current_state[key]
                        print(f"   ⚠️ UAV-{self.id}: Incompatibilité {key}: {current_state[key].shape} vs {value.shape}")
            
            # Ajouter les clés manquantes depuis l'état actuel
            for key, value in current_state.items():
                if key not in compatible_weights:
                    compatible_weights[key] = value
            
            self.model.load_state_dict(compatible_weights, strict=False)
            tee.secure_store(f"updated_model_{self.id}", "weights_updated")
            self.security_stats['tee_operations'] += 1

    def communicate_with_peers(self):
        """Communication sécurisée avec peers"""
        peer_weights = []
        peer_sizes = []
        peer_ids = []
        
        if self.protocol == "alltoall":
            for peer_id in self.group_ids:
                if peer_id != self.id and peer_id in self.global_results['uavs']:
                    delay = get_comm_delay(self.id, peer_id, self.positions)
                    yield self.env.timeout(delay)
                    
                    weights = self.global_results['uavs'][peer_id].get_model_weights()
                    peer_weights.append(weights)
                    peer_sizes.append(len(self.global_results['uavs'][peer_id].dataset))
                    peer_ids.append(peer_id)
                    
                    # Calcul du coût de communication
                    comm_size = sum(w.numel() * w.element_size() for w in weights.values())
                    self.communication_cost += comm_size
        
        elif self.protocol == "gossip":
            possible_peers = [pid for pid in self.group_ids 
                            if pid != self.id and pid in self.global_results['uavs']]
            if possible_peers:
                peer_id = random.choice(possible_peers)
                
                delay = get_comm_delay(self.id, peer_id, self.positions)
                yield self.env.timeout(delay)
                
                weights = self.global_results['uavs'][peer_id].get_model_weights()
                peer_weights.append(weights)
                peer_sizes.append(len(self.global_results['uavs'][peer_id].dataset))
                peer_ids.append(peer_id)
                
                comm_size = sum(w.numel() * w.element_size() for w in weights.values())
                self.communication_cost += comm_size
        
        # Détection locale - PAS de communication supplémentaire
        if peer_weights:
            threats = self.threat_detector.analyze_peer_updates(peer_weights, peer_ids)
            self.security_stats['threats_detected'] += len(threats)
            
            if threats:
                print(f"   🛡️ UAV-{self.id}: {len(threats)} menaces détectées localement")
        
        return peer_weights, peer_sizes, peer_ids

    def secure_intra_cluster_aggregation(self, peer_weights, peer_sizes, peer_ids):
        """Agrégation intra-cluster sécurisée avec filtrage des menaces"""
        if not peer_weights:
            return
        
        # Filtrer les mises à jour suspectes SANS communication
        threats = self.threat_detector.analyze_peer_updates(peer_weights, peer_ids)
        clean_weights, clean_ids = self.threat_detector.filter_suspicious_updates(
            peer_weights, peer_ids, threats
        )
        
        clean_sizes = []
        for clean_id in clean_ids:
            if clean_id in peer_ids:
                idx = peer_ids.index(clean_id)
                clean_sizes.append(peer_sizes[idx])
        
        all_weights = [self.get_model_weights()] + clean_weights
        all_sizes = [len(self.dataset)] + clean_sizes
        
        with self.tee.secure_context() as tee:
            aggregated_weights = weighted_fedavg(all_weights, all_sizes)
            tee.secure_store(f"aggregated_model_{self.id}", "aggregation_completed")
            self.security_stats['tee_operations'] += 1
        
        if aggregated_weights:
            self.set_model_weights(aggregated_weights)
            
        if threats:
            filtered_count = len(peer_weights) - len(clean_weights)
            print(f"   🔒 UAV-{self.id}: Agrégation sécurisée - {filtered_count} UAV suspects exclus")

    def inter_cluster_communication(self):
        """Communication inter-clusters sécurisée avec coefficient alpha"""
        if not self.is_cluster_leader:
            return
            
        print(f"   🌐🔒 UAV-{self.id} (Chef cluster {self.cluster_id}): Communication inter-clusters sécurisée (α={self.alpha_inter_cluster})")
        
        # Obtenir le modèle actuel du cluster (après agrégation intra-cluster)
        local_cluster_model = self.get_model_weights()
        
        other_cluster_models = []
        other_cluster_sizes = []
        other_leader_ids = []
        
        for cluster_idx in range(len(self.cluster_manager.groups)):
            if cluster_idx != self.cluster_id:
                leader_index = self.global_results['current_round'] % len(self.cluster_manager.groups[cluster_idx])
                other_leader_id = self.cluster_manager.groups[cluster_idx][leader_index]
                
                if other_leader_id in self.global_results['uavs']:
                    delay = get_comm_delay(self.id, other_leader_id, self.positions)
                    yield self.env.timeout(delay)
                    
                    other_model = self.global_results['uavs'][other_leader_id].get_model_weights()
                    other_cluster_models.append(other_model)
                    other_leader_ids.append(other_leader_id)
                    
                    other_cluster_size = sum(
                        len(self.global_results['uavs'][uav_id].dataset) 
                        for uav_id in self.cluster_manager.groups[cluster_idx]
                        if uav_id in self.global_results['uavs']
                    )
                    other_cluster_sizes.append(other_cluster_size)
                    
                    comm_size = sum(w.numel() * w.element_size() for w in other_model.values())
                    self.communication_cost += comm_size
        
        # Détection de menaces sur les modèles inter-clusters + Agrégation avec alpha
        if other_cluster_models:
            threats = self.threat_detector.analyze_peer_updates(other_cluster_models, other_leader_ids)
            clean_models, clean_leader_ids = self.threat_detector.filter_suspicious_updates(
                other_cluster_models, other_leader_ids, threats
            )
            
            clean_cluster_sizes = []
            for clean_id in clean_leader_ids:
                if clean_id in other_leader_ids:
                    idx = other_leader_ids.index(clean_id)
                    clean_cluster_sizes.append(other_cluster_sizes[idx])
            
            # Appliquer l'agrégation avec coefficient alpha
            with self.tee.secure_context() as tee:
                aggregated_model = weighted_fedavg_with_alpha(
                    local_model=local_cluster_model,
                    external_models=clean_models,
                    external_weights=clean_cluster_sizes,
                    alpha=self.alpha_inter_cluster
                )
                tee.secure_store(f"inter_cluster_alpha_model_{self.id}", "alpha_aggregation_completed")
                self.security_stats['tee_operations'] += 1
            
            if aggregated_model:
                self.set_model_weights(aggregated_model)
                print(f"   ✅🔒 Chef {self.id}: Modèle mis à jour avec coefficient α={self.alpha_inter_cluster}")
                print(f"     💡 Influence: {(1-self.alpha_inter_cluster)*100:.1f}% local + {self.alpha_inter_cluster*100:.1f}% externes")

    def broadcast_to_cluster_members(self):
        """Diffuser le modèle agrégé aux membres du cluster"""
        if not self.is_cluster_leader:
            return
            
        print(f"   📡🔒 Chef {self.id}: Diffusion du modèle agrégé avec α aux membres du cluster {self.cluster_id}")
        
        leader_model = self.get_model_weights()
        
        # Diffuser aux autres membres du cluster
        for member_id in self.group_ids:
            if member_id != self.id and member_id in self.global_results['uavs']:
                # Délai de communication intra-cluster
                delay = get_comm_delay(self.id, member_id, self.positions)
                yield self.env.timeout(delay)
                
                # Le membre reçoit le modèle du chef
                self.global_results['uavs'][member_id].receive_leader_model(leader_model)
                
                # Coût de communication
                comm_size = sum(w.numel() * w.element_size() for w in leader_model.values())
                self.communication_cost += comm_size

    def receive_leader_model(self, leader_model):
        """Recevoir le modèle du chef de cluster"""
        if not self.is_cluster_leader:
            self.set_model_weights(leader_model)
            print(f"   📥🔒 UAV-{self.id}: Modèle avec coefficient α reçu du chef de cluster")

    def secure_federated_learning_process(self):
        """Processus principal d'apprentissage fédéré sécurisé avec coefficient alpha"""
        
        # Synchronisation initiale
        yield self.env.timeout(0.1)
        
        for round_num in range(self.config['fl_rounds']):
            greedy_status = " (Greedy)" if self.enable_greedy else " (Standard)"
            model_info = " [CIFAR-10 de test_fin.py]" if self.config['dataset'] == 'CIFAR-10' else " [MNIST]"
            print(f"🔄🔒 UAV-{self.id}: Round sécurisé {round_num + 1}/{self.config['fl_rounds']}{greedy_status}{model_info}")
            
            self.global_results['current_round'] = round_num
            
            # Élection du chef de cluster
            leader_id = self.cluster_manager.elect_cluster_leader(self.cluster_id, round_num)
            self.is_cluster_leader = (self.id == leader_id)
            
            if self.is_cluster_leader:
                print(f"   👑🔒 UAV-{self.id}: Chef sécurisé du cluster {self.cluster_id} (α={self.alpha_inter_cluster})")
            
            # 1. Entraînement local sécurisé avec modèle de test_fin.py
            local_loss = self.secure_local_training()
            
            # Synchronisation avant communication
            yield self.env.timeout(0.5)
            
            # 2. Communication intra-cluster sécurisée
            peer_weights, peer_sizes, peer_ids = yield from self.communicate_with_peers()
            
            # 3. Agrégation intra-cluster sécurisée
            self.secure_intra_cluster_aggregation(peer_weights, peer_sizes, peer_ids)
            
            # Synchronisation avant inter-cluster
            yield self.env.timeout(0.2)
            
            # 4. Communication inter-clusters sécurisée AVEC COEFFICIENT ALPHA
            if self.is_cluster_leader:
                yield from self.inter_cluster_communication()
                
                # 5. Diffusion aux membres du cluster
                yield from self.broadcast_to_cluster_members()
            else:
                # Les non-chefs attendent de recevoir le modèle du chef
                yield self.env.timeout(1.0)
            
            # Synchronisation finale
            yield self.env.timeout(0.2)
            
            # Évaluation du modèle
            accuracy = evaluate_model(self.model, self.test_loader)
            self.round_accuracies.append(accuracy)
            
            # Enregistrer les résultats
            result_entry = {
                'uav_id': self.id,
                'round': round_num,
                'accuracy': accuracy,
                'loss': local_loss,
                'is_leader': self.is_cluster_leader,
                'greedy_enabled': self.enable_greedy,
                'tee_enabled': True,
                'alpha_inter_cluster': self.alpha_inter_cluster,
                'alpha_used': self.alpha_inter_cluster if self.is_cluster_leader else None,
                'threats_detected': self.security_stats['threats_detected'],
                'tee_operations': self.security_stats['tee_operations'],
                'model_from_test_fin': self.config['dataset'] == 'CIFAR-10'
            }
            
            if self.enable_greedy:
                greedy_status = self.model.get_greedy_status()
                result_entry.update({
                    'greedy_depth': greedy_status['current_depth'],
                    'greedy_max_depth': greedy_status['max_depth'],
                    'greedy_history_count': len(self.greedy_history)
                })
            
            self.global_results['all_accuracies'].append(result_entry)
            
            # Affichage des résultats avec info modèle de test_fin.py + alpha
            leader_status = f" (CHEF α={self.alpha_inter_cluster})" if self.is_cluster_leader else ""
            if self.enable_greedy:
                greedy_info = f" [Greedy FC:{self.model.current_fc_depth}/{self.model.max_fc_layers}]"
            else:
                greedy_info = " [Standard]"
            
            model_status = " [CIFAR-10 de test_fin.py]" if self.config['dataset'] == 'CIFAR-10' else " [MNIST]"
            security_info = f" [TEE:{self.security_stats['tee_operations']}ops, Menaces:{self.security_stats['threats_detected']}]"
            
            print(f"   📊🔒 Loss: {local_loss:.4f}, Accuracy: {accuracy:.4f}{leader_status}{greedy_info}{model_status}{security_info}")

    def get_security_report(self):
        """Génère un rapport de sécurité complet avec alpha"""
        tee_status = self.tee.get_security_status()
        
        return {
            'uav_id': self.id,
            'tee_status': tee_status,
            'security_stats': self.security_stats,
            'alpha_inter_cluster': self.alpha_inter_cluster,
            'greedy_history': self.greedy_history if self.enable_greedy else None,
            'model_from_test_fin': self.config['dataset'] == 'CIFAR-10'
        }

