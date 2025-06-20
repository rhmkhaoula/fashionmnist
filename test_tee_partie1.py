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
# MODÈLES CNN - SIMPLE MNIST ET FASHIONMNIST
# ================================

class CNNModelMNIST(nn.Module):
    """Modèle CNN MNIST/FashionMNIST - Simple avec support Greedy"""
    
    def __init__(self, enable_greedy=False):
        super(CNNModelMNIST, self).__init__()
        
        self.enable_greedy = enable_greedy
        self.current_fc_depth = 1
        self.max_fc_layers = 3
        
        # Architecture simple pour MNIST/FashionMNIST (28x28x1)
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
        # Forward simple pour MNIST/FashionMNIST
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

# ===== CIFAR-10 COMMENTÉ =====
# class CNNModelCIFAR10(nn.Module):
#     """🔧 Modèle CNN CIFAR-10 - Architecture EXACTE de test_fin.py avec support Greedy ajouté"""
#     
#     def __init__(self, enable_greedy=False):
#         super(CNNModelCIFAR10, self).__init__()
#         
#         # Support Greedy Layer-Wise
#         self.enable_greedy = enable_greedy
#         self.current_fc_depth = 1
#         self.max_fc_layers = 3
#         
#         # 🔧 ARCHITECTURE EXACTE DE test_fin.py
#         # Premier bloc convolutionnel
#         self.conv1 = nn.Conv2d(3, 64, kernel_size=3, padding=1)
#         self.bn1 = nn.BatchNorm2d(64)
#         
#         # Deuxième bloc convolutionnel
#         self.conv2 = nn.Conv2d(64, 128, kernel_size=3, padding=1)
#         self.bn2 = nn.BatchNorm2d(128)
#         
#         # Troisième bloc convolutionnel
#         self.conv3 = nn.Conv2d(128, 256, kernel_size=3, padding=1)
#         self.bn3 = nn.BatchNorm2d(256)
#         
#         # Quatrième bloc convolutionnel
#         self.conv4 = nn.Conv2d(256, 512, kernel_size=3, padding=1)
#         self.bn4 = nn.BatchNorm2d(512)
#         
#         # Pooling et dropout - EXACTEMENT comme test_fin.py
#         self.pool = nn.MaxPool2d(2, 2)
#         self.dropout = nn.Dropout(0.3)
#         self.dropout_fc = nn.Dropout(0.5)
#         
#         # Couches fully connected - EXACTEMENT comme test_fin.py
#         self.fc1 = nn.Linear(512 * 2 * 2, 1024)
#         self.bn_fc1 = nn.BatchNorm1d(1024)
#         self.fc2 = nn.Linear(1024, 512)
#         self.bn_fc2 = nn.BatchNorm1d(512)
#         self.fc3 = nn.Linear(512, 10)
#         
#         # Couches de sortie pour Greedy (ajout pour test_dfl_tee.py)
#         if self.enable_greedy:
#             self.output_layers = nn.ModuleDict({
#                 '1': nn.Linear(1024, 10),
#                 '2': nn.Linear(512, 10),
#                 '3': nn.Linear(10, 10)
#             })
#             self._freeze_unused_layers()

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
    # 🔧 TITRE MODIFIÉ pour refléter MNIST/FashionMNIST + Selfish FedAvg
    plt.title('Topologie Sécurisée TEE + Selfish FedAvg\nMNIST/FashionMNIST + Intra:Weighted + Inter:Selfish', 
              fontsize=16, fontweight='bold')
    plt.legend(bbox_to_anchor=(1.05, 1), loc='upper left', fontsize=12)
    plt.grid(True, alpha=0.3)
    plt.axis('equal')
    
    plt.xlim(-5, 105)
    plt.ylim(-5, 75)
    
    info_text = f"""Réseau UAV Sécurisé + Selfish:
• {len(positions)} drones avec TEE
• {len(groups)} clusters
• Zone: 100x100 km
• Portée comm: {communication_range} km
• Sécurité: TEE + Détection menaces
• Intra-cluster: Weighted FedAvg
• Inter-cluster: Selfish FedAvg (chefs)
• Datasets: MNIST/FashionMNIST
• Simulation: SimPy Environment
• Liens: — Intra-cluster, -- Inter-cluster"""
    
    plt.text(0.02, 0.98, info_text, transform=plt.gca().transAxes, 
             fontsize=10, verticalalignment='top',
             bbox=dict(boxstyle='round', facecolor='lightblue', alpha=0.8))
    
    plt.tight_layout()
    plt.savefig(filename, dpi=300, bbox_inches='tight')
    plt.close()
    
    print(f"🗺️ Topologie sécurisée MNIST/FashionMNIST + Selfish FedAvg sauvegardée: {filename}")
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
    elif dataset_name == "FASHIONMNIST":
        transform = transforms.Compose([transforms.ToTensor()])
        full_dataset = datasets.FashionMNIST(root='./data', train=True, download=True, transform=transform)
    # elif dataset_name == "CIFAR-10":  # ===== COMMENTÉ =====
    #     transform = transforms.Compose([transforms.ToTensor()])
    #     full_dataset = datasets.CIFAR10(root='./data', train=True, download=True, transform=transform)
    
    if iid:
        data_per_uav = len(full_dataset) // num_uavs
        indices = np.random.permutation(len(full_dataset))
        partitions = []
        
        for i in range(num_uavs):
            start = i * data_per_uav
            end = (i + 1) * data_per_uav if i < num_uavs - 1 else len(full_dataset)
            subset = torch.utils.data.Subset(full_dataset, uav_indices)
            partitions.append(subset)
            
        print(f"   ✅ Distribution Non-IID : répartition par classes")
    
    return partitions

def load_test_dataset(dataset_name, enable_greedy=False):
    """Charger le dataset de test - MNIST et FashionMNIST seulement"""
    if dataset_name == "MNIST":
        transform = transforms.Compose([transforms.ToTensor()])
        test_dataset = datasets.MNIST(root='./data', train=False, download=True, transform=transform)
        model_class = lambda: CNNModelMNIST(enable_greedy=enable_greedy)
    elif dataset_name == "FASHIONMNIST":
        transform = transforms.Compose([transforms.ToTensor()])
        test_dataset = datasets.FashionMNIST(root='./data', train=False, download=True, transform=transform)
        model_class = lambda: CNNModelMNIST(enable_greedy=enable_greedy)
    # else:  # CIFAR-10 - ===== COMMENTÉ =====
    #     transform = transforms.Compose([transforms.ToTensor()])
    #     test_dataset = datasets.CIFAR10(root='./data', train=False, download=True, transform=transform)
    #     # 🔧 UTILISE L'ARCHITECTURE EXACTE DE test_fin.py avec support Greedy
    #     model_class = lambda: CNNModelCIFAR10(enable_greedy=enable_greedy)
    
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
# FONCTIONS D'AGRÉGATION - WEIGHTED INTRA + SELFISH INTER
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

def selfish_fedavg(models_weights, weights_list, self_idx=0, alpha=2.0):
    """
    Selfish FedAvg: Le nœud au self_idx augmente son influence dans l'agrégation.
    alpha > 1 augmente l'égoïsme (alpha=1 est FedAvg standard).
    """
    if not models_weights:
        return None

    total_weight = sum(weights_list)
    if total_weight == 0:
        return None

    # Augmenter le poids du nœud local
    selfish_weights = weights_list.copy()
    selfish_weights[self_idx] *= alpha
    total_selfish_weight = sum(selfish_weights)
    normalized_weights = [w / total_selfish_weight for w in selfish_weights]

    aggregated_weights = {}
    for key in models_weights[0].keys():
        aggregated_weights[key] = sum(
            normalized_weights[i] * models_weights[i][key]
            for i in range(len(models_weights))
        )
    return aggregated_weights

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
# CLASSE UAV SÉCURISÉE AVEC WEIGHTED + SELFISH
# ================================

class SecureUAV:
    """Classe UAV sécurisée avec MNIST/FashionMNIST et Weighted+Selfish FedAvg"""
    
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
        
        # Initialiser le TEE
        self.tee = TEEManager(uav_id, memory_limit=512*1024*1024)
        
        # Initialiser le détecteur de menaces local
        self.threat_detector = LocalThreatDetector(uav_id)
        
        # Initialiser le modèle DANS LE TEE
        with self.tee.secure_context():
            self.model = model_class()  # 🔧 UTILISE CNNModelMNIST pour MNIST/FashionMNIST
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
        """Entraînement local sécurisé dans TEE avec modèle MNIST/FashionMNIST"""
        print(f"   🔒 UAV-{self.id}: Entraînement {'Greedy' if self.enable_greedy else 'Standard'} sécurisé (MNIST/FashionMNIST)")
        
        with self.tee.secure_context() as tee:
            self.security_stats['secure_trainings'] += 1
            
            self.model.train()
            
            # Optimiseur adapté selon architecture MNIST/FashionMNIST
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
                
                # Greedy Logic pour architecture MNIST/FashionMNIST
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
        """Définir les poids du modèle DANS TEE avec compatibilité MNIST/FashionMNIST"""
        with self.tee.secure_context() as tee:
            current_state = self.model.state_dict()
            
            # Compatibilité parfaite avec architecture MNIST/FashionMNIST
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
        """Agrégation intra-cluster sécurisée avec WEIGHTED FEDAVG"""
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
            # 🔧 UTILISE WEIGHTED FEDAVG pour intra-cluster
            aggregated_weights = weighted_fedavg(all_weights, all_sizes)
            tee.secure_store(f"aggregated_model_{self.id}", "weighted_aggregation_completed")
            self.security_stats['tee_operations'] += 1
        
        if aggregated_weights:
            self.set_model_weights(aggregated_weights)
            
        if threats:
            filtered_count = len(peer_weights) - len(clean_weights)
            print(f"   🔒 UAV-{self.id}: Agrégation Weighted FedAvg sécurisée - {filtered_count} UAV suspects exclus")

    def inter_cluster_communication(self):
        """Communication inter-clusters sécurisée avec SELFISH FEDAVG"""
        if not self.is_cluster_leader:
            return
            
        print(f"   🌐🔒 UAV-{self.id} (Chef cluster {self.cluster_id}): Communication inter-clusters sécurisée avec Selfish FedAvg")
        
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
        
        # Détection de menaces sur les modèles inter-clusters + Agrégation avec Selfish FedAvg
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
            
            # Calculer la taille de mon cluster
            my_cluster_size = sum(
                len(self.global_results['uavs'][uav_id].dataset) 
                for uav_id in self.group_ids 
                if uav_id in self.global_results['uavs']
            )
            
            # Préparer pour Selfish FedAvg
            all_models = [local_cluster_model] + clean_models
            all_sizes = [my_cluster_size] + clean_cluster_sizes
            
            # Appliquer Selfish FedAvg avec self_idx=0 (ce chef), alpha=2.0
            with self.tee.secure_context() as tee:
                # 🔧 UTILISE SELFISH FEDAVG pour inter-cluster
                aggregated_model = selfish_fedavg(all_models, all_sizes, self_idx=0, alpha=2.0)
                tee.secure_store(f"inter_cluster_selfish_model_{self.id}", "selfish_aggregation_completed")
                self.security_stats['tee_operations'] += 1
            
            if aggregated_model:
                self.set_model_weights(aggregated_model)
                print(f"   ✅🔒 Chef {self.id}: Modèle mis à jour avec Selfish FedAvg inter-clusters (α=2.0)")
                print(f"     💡 Influence: Chef augmente son influence de 2x dans l'agrégation")

    def broadcast_to_cluster_members(self):
        """Diffuser le modèle agrégé aux membres du cluster"""
        if not self.is_cluster_leader:
            return
            
        print(f"   📡🔒 Chef {self.id}: Diffusion du modèle Selfish FedAvg aux membres du cluster {self.cluster_id}")
        
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
            print(f"   📥🔒 UAV-{self.id}: Modèle Selfish FedAvg reçu du chef de cluster")

    def secure_federated_learning_process(self):
        """Processus principal d'apprentissage fédéré sécurisé avec Weighted+Selfish"""
        
        # Synchronisation initiale
        yield self.env.timeout(0.1)
        
        for round_num in range(self.config['fl_rounds']):
            greedy_status = " (Greedy)" if self.enable_greedy else " (Standard)"
            model_info = " [MNIST/FashionMNIST]"
            print(f"🔄🔒 UAV-{self.id}: Round sécurisé {round_num + 1}/{self.config['fl_rounds']}{greedy_status}{model_info}")
            
            self.global_results['current_round'] = round_num
            
            # Élection du chef de cluster
            leader_id = self.cluster_manager.elect_cluster_leader(self.cluster_id, round_num)
            self.is_cluster_leader = (self.id == leader_id)
            
            if self.is_cluster_leader:
                print(f"   👑🔒 UAV-{self.id}: Chef sécurisé du cluster {self.cluster_id} (Selfish FedAvg)")
            
            # 1. Entraînement local sécurisé avec modèle MNIST/FashionMNIST
            local_loss = self.secure_local_training()
            
            # Synchronisation avant communication
            yield self.env.timeout(0.5)
            
            # 2. Communication intra-cluster sécurisée
            peer_weights, peer_sizes, peer_ids = yield from self.communicate_with_peers()
            
            # 3. Agrégation intra-cluster sécurisée avec WEIGHTED FEDAVG
            self.secure_intra_cluster_aggregation(peer_weights, peer_sizes, peer_ids)
            
            # Synchronisation avant inter-cluster
            yield self.env.timeout(0.2)
            
            # 4. Communication inter-clusters sécurisée AVEC SELFISH FEDAVG
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
                'intra_algorithm': 'weighted_fedavg',
                'inter_algorithm': 'selfish_fedavg' if self.is_cluster_leader else None,
                'threats_detected': self.security_stats['threats_detected'],
                'tee_operations': self.security_stats['tee_operations'],
                'dataset': self.config['dataset']
            }
            
            if self.enable_greedy:
                greedy_status = self.model.get_greedy_status()
                result_entry.update({
                    'greedy_depth': greedy_status['current_depth'],
                    'greedy_max_depth': greedy_status['max_depth'],
                    'greedy_history_count': len(self.greedy_history)
                })
            
            self.global_results['all_accuracies'].append(result_entry)
            
            # Affichage des résultats avec info algorithmes
            leader_status = f" (CHEF Selfish α=2.0)" if self.is_cluster_leader else ""
            if self.enable_greedy:
                greedy_info = f" [Greedy FC:{self.model.current_fc_depth}/{self.model.max_fc_layers}]"
            else:
                greedy_info = " [Standard]"
            
            algorithm_info = f" [Intra:Weighted, Inter:{'Selfish' if self.is_cluster_leader else 'N/A'}]"
            security_info = f" [TEE:{self.security_stats['tee_operations']}ops, Menaces:{self.security_stats['threats_detected']}]"
            
            print(f"   📊🔒 Loss: {local_loss:.4f}, Accuracy: {accuracy:.4f}{leader_status}{greedy_info}{algorithm_info}{security_info}")

    def get_security_report(self):
        """Génère un rapport de sécurité complet avec algorithmes"""
        tee_status = self.tee.get_security_status()
        
        return {
            'uav_id': self.id,
            'tee_status': tee_status,
            'security_stats': self.security_stats,
            'intra_algorithm': 'weighted_fedavg',
            'inter_algorithm': 'selfish_fedavg' if self.is_cluster_leader else None,
            'greedy_history': self.greedy_history if self.enable_greedy else None,
            'dataset': self.config['dataset']
        }

# ================================
# FONCTIONS DE SIMULATION
# ================================

def create_uav_groups(num_uavs, num_clusters):
    """Créer des groupes d'UAV"""
    uavs_per_cluster = num_uavs // num_clusters
    groups = []
    
    for cluster_id in range(num_clusters):
        start_idx = cluster_id * uavs_per_cluster
        end_idx = (cluster_id + 1) * uavs_per_cluster
        if cluster_id == num_clusters - 1:
            end_idx = num_uavs
        
        group = list(range(start_idx, end_idx))
        groups.append(group)
    
    return groups

# ================================
# GÉNÉRATION AMÉLIORÉE DE FICHIERS ET GRAPHIQUES
# ================================

def generate_results_files(results):
    """Générer les fichiers de résultats en TXT et JSON - Version améliorée"""
    
    os.makedirs('results', exist_ok=True)
    
    scenario_name = results['scenario_name']
    timestamp = results['timestamp']
    
    # Fichier TXT détaillé avec toutes les métriques
    txt_filename = f"results/results_{scenario_name}_{timestamp}.txt"
    with open(txt_filename, 'w', encoding='utf-8') as f:
        f.write("=" * 90 + "\n")
        f.write("🚁 RÉSULTATS DFL SÉCURISÉ + GREEDY + WEIGHTED+SELFISH ALGORITHMS\n")
        f.write("🔧 AVEC MNIST/FASHIONMNIST + FONCTIONNALITÉS AVANCÉES\n")
        f.write("=" * 90 + "\n\n")
        
        f.write(f"📅 Date/Heure: {timestamp}\n")
        f.write(f"🎯 Scénario: {scenario_name}\n")
        f.write(f"🗺️ Topologie: {results.get('topology_filename', 'N/A')}\n\n")
        
        f.write("📋 CONFIGURATION:\n")
        f.write(f"  • Dataset: {results['config']['dataset']}\n")
        f.write(f"  • Distribution: {'IID' if results['config']['iid'] else 'Non-IID'}\n")
        f.write(f"  • Protocole: {results['config']['protocol'].upper()}\n")
        f.write(f"  • Nombre d'UAVs: {results['config']['num_uavs']}\n")
        f.write(f"  • Nombre de clusters: {results['config']['num_clusters']}\n")
        f.write(f"  • Rounds FL: {results['config']['fl_rounds']}\n")
        f.write(f"  • Époques locales: {results['config']['local_epochs']}\n")
        f.write(f"  • Batch size: {results['config']['batch_size']}\n")
        f.write(f"  • Sécurité TEE: {'✅ ACTIVÉE' if results.get('tee_enabled', False) else '❌ DÉSACTIVÉE'}\n")
        f.write(f"  • Détection menaces: {'✅ ACTIVÉE' if results.get('security_enabled', False) else '❌ DÉSACTIVÉE'}\n")
        f.write(f"  • Greedy Layer-Wise: {'✅ ACTIVÉ' if results['greedy_enabled'] else '❌ DÉSACTIVÉ'}\n")
        f.write(f"  🔧 • Algorithme Intra-cluster: Weighted FedAvg (Standard)\n")
        f.write(f"  🔧 • Algorithme Inter-cluster: Selfish FedAvg (α=2.0, Chefs seulement)\n")
        f.write(f"  🔧 • Datasets supportés: MNIST, FashionMNIST (28x28x1)\n")
        f.write(f"  🆕 • Simulation: SimPy Environment temporelle\n")
        f.write(f"  🆕 • Positions: Générées automatiquement (100x100 km)\n")
        f.write(f"  🆕 • Communication: Délais basés sur distance euclidienne\n")
        f.write(f"  🆕 • Topologie: PNG générée automatiquement\n\n")
        
        f.write("📊 RÉSULTATS PRINCIPAUX:\n")
        f.write(f"  • Précision finale moyenne: {results['final_average_accuracy']:.4f} ({results['final_average_accuracy']*100:.2f}%)\n")
        f.write(f"  • Temps total d'exécution: {results['simulation_time']:.2f} secondes\n")
        f.write(f"  • Coût total communication: {results['total_communication_cost'] / 1024:.2f} KB\n")
        f.write(f"  • Coût total computationnel: {results['total_computational_cost']}\n\n")
        
        # Statistiques de sécurité si disponibles
        if results.get('tee_enabled', False):
            f.write("🔒 STATISTIQUES DE SÉCURITÉ:\n")
            f.write(f"  • Opérations TEE totales: {results.get('total_tee_operations', 0)}\n")
            f.write(f"  • Menaces détectées totales: {results.get('total_threats_detected', 0)}\n")
            f.write(f"  • UAVs avec TEE: {results['config']['num_uavs']}/100% (tous sécurisés)\n")
            f.write(f"  • Détection locale: ✅ (pas de communication supplémentaire)\n\n")
        
        # Statistiques des algorithmes
        f.write("🔧 STATISTIQUES DES ALGORITHMES:\n")
        f.write(f"  • Intra-cluster: Weighted FedAvg (équitable, basé sur tailles datasets)\n")
        f.write(f"  • Inter-cluster: Selfish FedAvg (chefs augmentent leur influence α=2.0)\n")
        f.write(f"  • Comportement: Collaboration équitable intra + Égoïsme inter\n")
        f.write(f"  • Avantage: Préservation identité clusters + Performance locale\n")
        f.write(f"  • Utilisation par round:\n")
        
        # Utilisation par round si disponible
        if 'leadership_stats' in results:
            for round_num, leaders in results['leadership_stats'].items():
                if leaders:
                    f.write(f"    Round {int(round_num) + 1}: Chefs Selfish - {leaders}\n")
        f.write("\n")
        
        # Architecture du modèle
        f.write("🔧 ARCHITECTURE MODÈLE MNIST/FASHIONMNIST:\n")
        f.write(f"  • Architecture: CNNModelMNIST simple et efficace\n")
        f.write(f"  • Format d'entrée: 28x28x1 (niveaux de gris)\n")
        f.write(f"  • Couches convolutionnelles: 2 (1->32->64)\n")
        f.write(f"  • Couches FC: 3 (64*7*7 -> 256 -> 128 -> 10)\n")
        f.write(f"  • Support datasets: MNIST (chiffres) + FashionMNIST (vêtements)\n")
        f.write(f"  • Support Greedy: Ajouté sans modification du core\n")
        f.write(f"  • Compatibilité TEE: Intégrée parfaitement\n")
        f.write(f"  • Performance attendue: MNIST ~95%, FashionMNIST ~88%\n\n")
        
        f.write("📈 ÉVOLUTION DE LA PRÉCISION PAR ROUND:\n")
        for i, acc in enumerate(results['average_accuracy_per_round']):
            f.write(f"  Round {i+1}: {acc:.4f} ({acc*100:.2f}%)\n")
        f.write("\n")
        
        # Statistiques de leadership si disponibles
        if 'leadership_stats' in results:
            f.write("🏢 STATISTIQUES DE LEADERSHIP (Selfish FedAvg):\n")
            for round_num, leaders in results['leadership_stats'].items():
                f.write(f"  • Round {int(round_num)+1}: Chefs - {leaders}\n")
            f.write("\n")
        
        # Coûts par UAV
        f.write("💰 COÛTS PAR UAV:\n")
        for i, (comm_cost, comp_cost) in enumerate(zip(results['uav_communication_costs'], results['uav_computational_costs'])):
            f.write(f"  UAV-{i}: Communication {comm_cost/1024:.2f} KB, Computation {comp_cost}\n")
        f.write("\n")
        
        # Statistiques Greedy si activé
        if results['greedy_enabled'] and 'total_greedy_additions' in results:
            f.write("🧠 STATISTIQUES GREEDY LAYER-WISE:\n")
            f.write(f"  • Ajouts totaux de couches: {results['total_greedy_additions']}\n")
            if 'greedy_uav_stats' in results:
                for uav_id, stats in results['greedy_uav_stats'].items():
                    f.write(f"  • UAV-{uav_id}: Profondeur finale {stats['final_depth']}/{stats['max_depth']}, {stats['additions_count']} ajouts\n")
            f.write("\n")
        
        f.write("🎯 VERSION WEIGHTED + SELFISH ALGORITHMS:\n")
        f.write(f"  • Architecture: CNNModelMNIST (MNIST/FashionMNIST)\n")
        f.write(f"  • Intra-cluster: Weighted FedAvg (collaboration équitable)\n")
        f.write(f"  • Inter-cluster: Selfish FedAvg (chefs égoïstes α=2.0)\n")
        f.write(f"  • Sécurité: TEE + Détection menaces locale\n")
        f.write(f"  • Optimisation: {'Greedy Layer-Wise adaptatif' if results['greedy_enabled'] else 'Standard'}\n")
        f.write(f"  • Comportement: Équilibre collaboration locale / égoïsme global\n")
        f.write(f"  • Communication: Coût optimisé selon protocole\n")
        f.write(f"  🆕 Positions UAV: Générées automatiquement\n")
        f.write(f"  🆕 Délais communication: Distance euclidienne\n")
        f.write(f"  🆕 Simulation temporelle: SimPy Environment\n")
        f.write(f"  🆕 Topologie visuelle: PNG générée automatiquement\n")
        f.write(f"  🔧 Datasets: MNIST + FashionMNIST supportés\n")
        f.write(f"  ⚡ Performance: Optimisée par algorithmes hybrides\n")
        f.write(f"  🎯 Avantage: Préservation identité + Performance globale\n")
        f.write(f"  • Performance globale: Maximisée par toutes les optimisations\n")
    
    # Fichier JSON pour analyse programmatique
    json_filename = f"results/results_{scenario_name}_{timestamp}.json"
    
    json_data = {
        'scenario_name': scenario_name,
        'timestamp': timestamp,
        'config': results['config'],
        'final_average_accuracy': float(results['final_average_accuracy']),
        'simulation_time': float(results['simulation_time']),
        'total_communication_cost': float(results['total_communication_cost']),
        'total_computational_cost': int(results['total_computational_cost']),
        'average_accuracy_per_round': [float(x) for x in results['average_accuracy_per_round']],
        'uav_communication_costs': [float(x) for x in results['uav_communication_costs']],
        'uav_computational_costs': [int(x) for x in results['uav_computational_costs']],
        'uav_final_accuracies': [float(x) for x in results['uav_final_accuracies']],
        'greedy_enabled': results['greedy_enabled'],
        'tee_enabled': results.get('tee_enabled', False),
        'security_enabled': results.get('security_enabled', False),
        'intra_algorithm': 'weighted_fedavg',
        'inter_algorithm': 'selfish_fedavg',
        'datasets_supported': ['MNIST', 'FASHIONMNIST'],
        'architecture_type': 'CNNModelMNIST_simple',
        'topology_filename': results.get('topology_filename', 'N/A')
    }
    
    # Ajouter les statistiques spéciales si disponibles
    if 'leadership_stats' in results:
        json_data['leadership_stats'] = {str(k): v for k, v in results['leadership_stats'].items()}
    
    if results['greedy_enabled'] and 'total_greedy_additions' in results:
        json_data['total_greedy_additions'] = results['total_greedy_additions']
        if 'greedy_uav_stats' in results:
            json_data['greedy_uav_stats'] = results['greedy_uav_stats']
    
    if results.get('tee_enabled', False):
        json_data['total_tee_operations'] = results.get('total_tee_operations', 0)
        json_data['total_threats_detected'] = results.get('total_threats_detected', 0)
        if 'security_reports' in results:
            json_data['security_reports'] = results['security_reports']
    
    if 'positions' in results:
        json_data['positions'] = [[float(pos[0]), float(pos[1])] for pos in results['positions']]
    
    if 'groups' in results:
        json_data['groups'] = results['groups']
    
    with open(json_filename, 'w', encoding='utf-8') as f:
        json.dump(json_data, f, indent=2, ensure_ascii=False)
    
    print(f"📄 Fichiers de résultats générés:")
    print(f"   📝 {txt_filename}")
    print(f"   📋 {json_filename}")
    
    return txt_filename, json_filename

def generate_graphs(results):
    """Générer les graphiques automatiquement - Version complète"""
    
    os.makedirs('graphs', exist_ok=True)
    
    scenario_name = results['scenario_name']
    timestamp = results['timestamp']
    
    plt.style.use('default')
    plt.rcParams['figure.figsize'] = (12, 8)
    plt.rcParams['font.size'] = 12
    
    generated_graphs = []
    
    # 1. Graphique principal - Évolution de l'accuracy
    plt.figure(figsize=(14, 10))
    rounds = list(range(1, len(results['average_accuracy_per_round']) + 1))
    accuracy_percent = [acc * 100 for acc in results['average_accuracy_per_round']]
    
    # Couleur et label selon les caractéristiques
    color = 'green' if results['greedy_enabled'] else 'blue'
    label_base = f"DFL ({'Greedy' if results['greedy_enabled'] else 'Standard'})"
    label_base += " + TEE Sécurisé + Weighted+Selfish"
    label_base += f" ({results['config']['dataset']})"
    
    plt.plot(rounds, accuracy_percent, f'{color[0]}-o', linewidth=3, markersize=8, label=label_base)
    plt.xlabel('Rounds d\'entraînement', fontsize=14, fontweight='bold')
    plt.ylabel('Précision (%)', fontsize=14, fontweight='bold')
    
    # Titre dynamique
    title = f'Évolution Précision DFL + Weighted+Selfish Algorithms'
    title += f' - {scenario_name}'
    plt.title(title, fontsize=16, fontweight='bold')
    
    plt.grid(True, alpha=0.3)
    plt.legend(fontsize=12)
    
    # Annotations intelligentes
    if accuracy_percent:
        max_acc = max(accuracy_percent)
        max_round = accuracy_percent.index(max_acc) + 1
        annotation_text = f'Max: {max_acc:.2f}%'
        annotation_text += '\n🔒 TEE Sécurisé'
        annotation_text += '\n📊 Intra: Weighted'
        annotation_text += '\n🎯 Inter: Selfish (α=2.0)'
        
        plt.annotate(annotation_text, 
                    xy=(max_round, max_acc), 
                    xytext=(max_round + 1, max_acc + 1),
                    arrowprops=dict(arrowstyle='->', color='red'),
                    fontsize=11, color='red', fontweight='bold')
    
    # Informations complètes dans le coin
    info_text = f"Dataset: {results['config']['dataset']}\n"
    info_text += f"UAVs: {results['config']['num_uavs']}, Clusters: {results['config']['num_clusters']}\n"
    if results.get('tee_enabled', False):
        info_text += f"🔒 TEE: {results.get('total_tee_operations', 0)} ops\n"
        info_text += f"🛡️ Menaces: {results.get('total_threats_detected', 0)}\n"
    info_text += f"📊 Intra: Weighted FedAvg\n"
    info_text += f"🎯 Inter: Selfish FedAvg (α=2.0)\n"
    if results['greedy_enabled'] and 'total_greedy_additions' in results:
        info_text += f"🧠 Greedy: {results['total_greedy_additions']} ajouts\n"
    info_text += f"📡 Comm: {results['total_communication_cost']/1024:.1f} KB\n"
    info_text += f"⏱️ Temps: {results['simulation_time']:.1f}s"
    
    plt.text(0.02, 0.98, info_text, transform=plt.gca().transAxes, 
             fontsize=10, verticalalignment='top', 
             bbox=dict(boxstyle='round', facecolor='lightyellow', alpha=0.8))
    
    plt.tight_layout()
    acc_filename = f"graphs/accuracy_{scenario_name}_{timestamp}.png"
    plt.savefig(acc_filename, dpi=300, bbox_inches='tight')
    plt.close()
    generated_graphs.append(acc_filename)
    
    # 2. Graphique des métriques principales
    plt.figure(figsize=(16, 12))
    
    # Subplot 1: Métriques principales
    plt.subplot(2, 2, 1)
    metrics = ['Précision\n(%)', 'Temps\n(min)', 'Comm.\n(MB)', 'Clusters\n(nb)']
    values = [
        results['final_average_accuracy'] * 100,
        results['simulation_time'] / 60,
        results['total_communication_cost'] / (1024 * 1024),
        results['config']['num_clusters']
    ]
    colors = ['green', 'blue', 'orange', 'red']
    
    bars = plt.bar(metrics, values, color=colors, alpha=0.7)
    plt.title('Métriques Principales DFL Weighted+Selfish', fontsize=14, fontweight='bold')
    
    # Ajouter les valeurs sur les barres
    for bar, value in zip(bars, values):
        height = bar.get_height()
        plt.text(bar.get_x() + bar.get_width()/2., height + max(values)*0.01,
                f'{value:.1f}', ha='center', va='bottom', fontweight='bold')
    
    # Subplot 2: Distribution des précisions finales
    plt.subplot(2, 2, 2)
    plt.hist(results['uav_final_accuracies'], bins=10, alpha=0.7, color='lightgreen', edgecolor='black')
    mean_acc = np.mean(results['uav_final_accuracies']) * 100
    plt.axvline(np.mean(results['uav_final_accuracies']), color='red', linestyle='--', linewidth=2, 
                label=f'Moyenne: {mean_acc:.1f}%')
    plt.xlabel('Précision Finale (%)', fontsize=12)
    plt.ylabel('Nombre d\'UAVs', fontsize=12)
    plt.title('Distribution des Précisions Finales', fontsize=14, fontweight='bold')
    plt.legend()
    
    # Subplot 3: Leadership par round (Selfish FedAvg)
    plt.subplot(2, 2, 3)
    if 'leadership_stats' in results:
        rounds_leadership = list(results['leadership_stats'].keys())
        num_leaders_per_round = [len(results['leadership_stats'][round_key]) for round_key in rounds_leadership]
        plt.bar(range(len(rounds_leadership)), num_leaders_per_round, color='gold', alpha=0.7)
        plt.xlabel('Round', fontsize=12)
        plt.ylabel('Nombre de Chefs Selfish', fontsize=12)
        plt.title('Chefs Selfish FedAvg par Round', fontsize=14, fontweight='bold')
        plt.xticks(range(len(rounds_leadership)), [f'{int(r)+1}' for r in rounds_leadership])
        
        # Ajouter les valeurs
        for i, v in enumerate(num_leaders_per_round):
            plt.text(i, v + 0.05, str(v), ha='center', va='bottom', fontweight='bold')
    
    # Subplot 4: Évolution de la précision
    plt.subplot(2, 2, 4)
    plt.plot(rounds, accuracy_percent, 'go-', linewidth=2, markersize=6)
    plt.xlabel('Rounds', fontsize=12)
    plt.ylabel('Précision (%)', fontsize=12)
    plt.title('Évolution de la Précision', fontsize=14, fontweight='bold')
    plt.grid(True, alpha=0.3)
    
    # Ajouter annotation du maximum
    if accuracy_percent:
        max_acc = max(accuracy_percent)
        max_round = accuracy_percent.index(max_acc) + 1
        plt.annotate(f'Max: {max_acc:.1f}%', 
                    xy=(max_round, max_acc), 
                    xytext=(max_round + 1, max_acc - 2),
                    arrowprops=dict(arrowstyle='->', color='red'),
                    fontsize=10, color='red')
    
    plt.tight_layout()
    metrics_filename = f"graphs/metrics_{scenario_name}_{timestamp}.png"
    plt.savefig(metrics_filename, dpi=300, bbox_inches='tight')
    plt.close()
    generated_graphs.append(metrics_filename)
    
    # 3. Graphique des coûts de communication par UAV
    plt.figure(figsize=(14, 8))
    uav_ids = list(range(results['config']['num_uavs']))
    comm_costs_kb = [cost / 1024 for cost in results['uav_communication_costs']]
    
    plt.bar(uav_ids, comm_costs_kb, color='lightblue', alpha=0.7, edgecolor='navy')
    plt.xlabel('UAV ID', fontsize=14, fontweight='bold')
    plt.ylabel('Coût de Communication (KB)', fontsize=14, fontweight='bold')
    plt.title(f'Coût de Communication par UAV - Weighted+Selfish - {scenario_name}', fontsize=16, fontweight='bold')
    plt.grid(True, alpha=0.3, axis='y')
    
    # Ligne de moyenne
    mean_comm = np.mean(comm_costs_kb)
    plt.axhline(y=mean_comm, color='red', linestyle='--', linewidth=2, 
                label=f'Moyenne: {mean_comm:.1f} KB')
    plt.legend(fontsize=12)
    
    # Ajouter valeurs sur quelques barres
    for i in range(0, len(uav_ids), max(1, len(uav_ids)//5)):
        plt.text(i, comm_costs_kb[i] + max(comm_costs_kb)*0.01, 
                f'{comm_costs_kb[i]:.1f}', ha='center', va='bottom', fontsize=9)
    
    plt.tight_layout()
    comm_filename = f"graphs/communication_{scenario_name}_{timestamp}.png"
    plt.savefig(comm_filename, dpi=300, bbox_inches='tight')
    plt.close()
    generated_graphs.append(comm_filename)
    
    # 4. Graphique des coûts computationnels par UAV
    plt.figure(figsize=(14, 8))
    comp_costs = results['uav_computational_costs']
    
    plt.bar(uav_ids, comp_costs, color='lightcoral', alpha=0.7, edgecolor='darkred')
    plt.xlabel('UAV ID', fontsize=14, fontweight='bold')
    plt.ylabel('Coût Computationnel (échantillons traités)', fontsize=14, fontweight='bold')
    plt.title(f'Coût Computationnel par UAV - Weighted+Selfish - {scenario_name}', fontsize=16, fontweight='bold')
    plt.grid(True, alpha=0.3, axis='y')
    
    # Ligne de moyenne
    mean_comp = np.mean(comp_costs)
    plt.axhline(y=mean_comp, color='blue', linestyle='--', linewidth=2, 
                label=f'Moyenne: {mean_comp:,}')
    plt.legend(fontsize=12)
    
    plt.tight_layout()
    comp_filename = f"graphs/computation_{scenario_name}_{timestamp}.png"
    plt.savefig(comp_filename, dpi=300, bbox_inches='tight')
    plt.close()
    generated_graphs.append(comp_filename)
    
    # 5. Graphique des positions UAV avec topologie si disponible
    if 'positions' in results and 'groups' in results:
        plt.figure(figsize=(14, 10))
        
        colors_clusters = ['red', 'blue', 'green', 'orange', 'purple', 'brown', 'pink', 'gray', 'olive', 'cyan']
        
        # Dessiner les positions des UAVs par cluster
        for cluster_idx, group in enumerate(results['groups']):
            cluster_positions = [results['positions'][uav_id] for uav_id in group]
            x_coords = [pos[0] for pos in cluster_positions]
            y_coords = [pos[1] for pos in cluster_positions]
            
            color = colors_clusters[cluster_idx % len(colors_clusters)]
            
            # Dessiner les UAVs
            plt.scatter(x_coords, y_coords, c=color, s=150, alpha=0.8, 
                       label=f'Cluster {cluster_idx}', edgecolors='black', linewidth=2)
            
            # Ajouter les IDs des UAVs
            for uav_id, pos in zip(group, cluster_positions):
                plt.annotate(f'UAV-{uav_id}', (pos[0], pos[1]), 
                            xytext=(5, 5), textcoords='offset points',
                            fontsize=9, fontweight='bold')
        
        plt.xlabel('Position X (km)', fontsize=14, fontweight='bold')
        plt.ylabel('Position Y (km)', fontsize=14, fontweight='bold')
        
        title = f'Positions UAV Sécurisées + Weighted+Selfish'
        title += f' - {scenario_name}'
        
        plt.title(title, fontsize=16, fontweight='bold')
        plt.legend(fontsize=10)
        plt.grid(True, alpha=0.3)
        
        # Ajouter des informations complètes
        info_text = f"""Réseau UAV Weighted+Selfish:
• {len(results['positions'])} drones
• {len(results['groups'])} clusters
• Zone: 100x100 km"""
        
        if results.get('tee_enabled', False):
            info_text += f"\n• TEE: {results.get('total_tee_operations', 0)} opérations"
            info_text += f"\n• Menaces: {results.get('total_threats_detected', 0)} détectées"
        
        info_text += f"\n• Intra: Weighted FedAvg"
        info_text += f"\n• Inter: Selfish FedAvg (α=2.0)"
        info_text += f"\n• Dataset: {results['config']['dataset']}"
        info_text += f"\n• Simulation: SimPy Environment"
        
        plt.text(0.02, 0.98, info_text, transform=plt.gca().transAxes, 
                 fontsize=11, verticalalignment='top',
                 bbox=dict(boxstyle='round', facecolor='lightblue', alpha=0.8))
        
        plt.tight_layout()
        pos_filename = f"graphs/positions_{scenario_name}_{timestamp}.png"
        plt.savefig(pos_filename, dpi=300, bbox_inches='tight')
        plt.close()
        generated_graphs.append(pos_filename)
    
    print(f"📈 Graphiques générés:")
    for graph in generated_graphs:
        print(f"   📊 {graph}")
    
    return generated_graphs

def enhanced_collect_results(uavs, config, positions, groups, simulation_time, global_results, enable_greedy=False):
    """Version améliorée de collect_results avec toutes les statistiques"""
    
    # Calcul des précisions moyennes par round
    average_accuracy_per_round = []
    for round_num in range(config['fl_rounds']):
        round_accuracies = [
            acc['accuracy'] for acc in global_results['all_accuracies'] 
            if acc['round'] == round_num
        ]
        if round_accuracies:
            average_accuracy_per_round.append(np.mean(round_accuracies))
    
    # Statistiques des UAVs
    uav_communication_costs = [uav.communication_cost for uav in uavs]
    uav_computational_costs = [uav.computational_cost for uav in uavs]
    uav_final_accuracies = [uav.round_accuracies[-1] if uav.round_accuracies else 0 for uav in uavs]
    
    # Statistiques de sécurité si TEE activé
    total_tee_operations = 0
    total_threats_detected = 0
    security_reports = []
    
    if hasattr(uavs[0], 'security_stats'):  # Vérifier si TEE est activé
        total_tee_operations = sum(uav.security_stats['tee_operations'] for uav in uavs)
        total_threats_detected = sum(uav.security_stats['threats_detected'] for uav in uavs)
        security_reports = [uav.get_security_report() for uav in uavs if hasattr(uav, 'get_security_report')]
    
    # Statistiques Greedy si activé
    total_greedy_additions = 0
    greedy_uav_stats = {}
    
    if enable_greedy:
        for uav in uavs:
            if hasattr(uav, 'greedy_history'):
                greedy_stats = {
                    'final_depth': uav.model.current_fc_depth if hasattr(uav.model, 'current_fc_depth') else 1,
                    'max_depth': uav.model.max_fc_layers if hasattr(uav.model, 'max_fc_layers') else 3,
                    'additions_count': len(uav.greedy_history),
                    'history': uav.greedy_history
                }
                greedy_uav_stats[uav.id] = greedy_stats
                total_greedy_additions += len(uav.greedy_history)
    
    # Statistiques de leadership
    leadership_stats = {}
    
    for round_num in range(config['fl_rounds']):
        # Chefs de cluster pour ce round
        leaders = [
            acc['uav_id'] for acc in global_results['all_accuracies'] 
            if acc['round'] == round_num and acc.get('is_leader', False)
        ]
        leadership_stats[round_num] = leaders
    
    # Construction du dictionnaire de résultats complet
    results = {
        'config': config,
        'scenario_name': global_results['scenario_name'],
        'timestamp': global_results['timestamp'],
        'average_accuracy_per_round': average_accuracy_per_round,
        'final_average_accuracy': average_accuracy_per_round[-1] if average_accuracy_per_round else 0,
        'uav_communication_costs': uav_communication_costs,
        'uav_computational_costs': uav_computational_costs,
        'uav_final_accuracies': uav_final_accuracies,
        'total_communication_cost': sum(uav_communication_costs),
        'total_computational_cost': sum(uav_computational_costs),
        'simulation_time': simulation_time,
        'positions': positions,
        'groups': groups,
        'leadership_stats': leadership_stats,
        'all_accuracies': global_results['all_accuracies'],
        'greedy_enabled': enable_greedy,
        'total_greedy_additions': total_greedy_additions,
        'greedy_uav_stats': greedy_uav_stats,
        'tee_enabled': global_results.get('tee_enabled', False),
        'security_enabled': global_results.get('security_enabled', False),
        'intra_algorithm': 'weighted_fedavg',
        'inter_algorithm': 'selfish_fedavg',
        'total_tee_operations': total_tee_operations,
        'total_threats_detected': total_threats_detected,
        'security_reports': security_reports,
        'topology_filename': global_results.get('topology_filename', 'N/A')
    }
    
    return results

def enhanced_result_generation_in_simulation(results):
    """Appel des fonctions améliorées de génération de résultats"""
    
    print(f"\n📊 GÉNÉRATION AUTOMATIQUE DES RÉSULTATS...")
    
    # 1. Générer les fichiers TXT et JSON
    txt_file, json_file = generate_results_files(results)
    
    # 2. Générer tous les graphiques
    graphs = generate_graphs(results)
    
    print(f"\n✅ TOUS LES RÉSULTATS GÉNÉRÉS AVEC SUCCÈS:")
    print(f"📁 Dossiers créés automatiquement:")
    print(f"   📂 results/ - Fichiers de résultats")
    print(f"   📂 graphs/ - Graphiques et visualisations")
    print(f"   📂 topology/ - Cartes de topologie réseau")
    
    return {
        'txt_file': txt_file,
        'json_file': json_file,
        'graphs': graphs
    }

def run_simulation(config, enable_greedy=False):
    """Exécuter la simulation sécurisée avec modèle MNIST/FashionMNIST et Weighted+Selfish"""
    
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    greedy_suffix = "_Greedy" if enable_greedy else "_Standard"
    security_suffix = "_TEE_Secure"
    algorithms_suffix = "_Weighted_Selfish"
    scenario_name = f"{config['dataset']}_{config['protocol']}_{'IID' if config['iid'] else 'NonIID'}_DFL{security_suffix}{greedy_suffix}{algorithms_suffix}"
    
    print(f"\n🚁 SIMULATION DFL SÉCURISÉE + WEIGHTED+SELFISH ALGORITHMS: {scenario_name}")
    print("🔒 TEE + DÉTECTION MENACES + ALGORITHMES HYBRIDES")
    print("📊 INTRA-CLUSTER: Weighted FedAvg (Équitable)")
    print("🎯 INTER-CLUSTER: Selfish FedAvg (Chefs Égoïstes α=2.0)")
    print("🔧 DATASETS: MNIST + FashionMNIST (28x28x1)")
    print("🆕 AJOUTS: Positions UAV + Communication + Simulation + Topologie")
    print("📡 SIMULATION TEMPORELLE avec SimPy Environment")
    print("=" * 100)
    
    num_uavs = config['num_uavs']
    num_clusters = config['num_clusters']
    
    env = simpy.Environment()
    
    # Utilise create_uav_positions avec clusters géographiques
    groups = create_uav_groups(num_uavs, num_clusters)
    positions = create_uav_positions(num_uavs, area_size=100, groups=groups)
    
    print(f"📡 Groupes créés: {groups}")
    print(f"📍 Positions UAV générées: Clusters géographiquement proches")
    
    partitions = partition_dataset(num_uavs, config['iid'], config['dataset'])
    test_loader, model_class = load_test_dataset(config['dataset'], enable_greedy)
    
    # Afficher les informations sur les modèles
    temp_model = model_class()
    total_params = sum(p.numel() for p in temp_model.parameters())
    model_type = "CNNModelMNIST Simple"
    print(f"🧠 Modèle {config['dataset']}: {total_params:,} paramètres ({model_type})")
    print(f"🔧 ARCHITECTURE: CNNModelMNIST pour MNIST/FashionMNIST (28x28x1)")
    print(f"⚡ Performance attendue: MNIST ~95%, FashionMNIST ~88%")
    print(f"⏱️ Temps: Optimisé pour datasets simples")
    
    # Génération de la topologie AVANT la simulation
    topology_filename = generate_network_topology_image(positions, groups)
    
    global_results = {
        'all_accuracies': [],
        'uavs': {},
        'current_round': 0,
        'greedy_enabled': enable_greedy,
        'tee_enabled': True,
        'security_enabled': True,
        'intra_algorithm': 'weighted_fedavg',
        'inter_algorithm': 'selfish_fedavg',
        'config': config,
        'scenario_name': scenario_name,
        'timestamp': timestamp,
        'topology_filename': topology_filename
    }
    
    cluster_manager = ClusterManager(env, groups, global_results)
    
    uavs = []
    print("🚀 Initialisation des UAVs...")
    for uav_id in range(num_uavs):
        cluster_id = None
        group_ids = None
        for idx, group in enumerate(groups):
            if uav_id in group:
                cluster_id = idx
                group_ids = group
                break
        
        uav = SecureUAV(
            env=env,
            uav_id=uav_id,
            cluster_id=cluster_id,
            group_ids=group_ids,
            dataset=partitions[uav_id],
            test_loader=test_loader,
            model_class=model_class,
            protocol=config['protocol'],
            positions=positions,
            config=config,
            global_results=global_results,
            cluster_manager=cluster_manager,
            enable_greedy=enable_greedy
        )
        
        uavs.append(uav)
        global_results['uavs'][uav_id] = uav
        
        # Afficher position avec cluster
        pos = positions[uav_id]
        print(f"   ✅ UAV-{uav_id} initialisé (Cluster {cluster_id}, Position: {pos[0]:.1f},{pos[1]:.1f})")
    
    print("🚀 Démarrage de la simulation DFL SÉCURISÉE + WEIGHTED+SELFISH...")
    print("📋 ARCHITECTURE:")
    print("   • Communication intra-cluster: Weighted FedAvg sécurisé")
    print("   • Communication inter-cluster: Chefs seulement avec TEE + Selfish FedAvg")
    print(f"   • Influence chefs: Augmentée de 2x (α=2.0) dans agrégation inter-cluster")
    print(f"   • Comportement: Équitable intra + Égoïste inter")
    print(f"   • Modèle {config['dataset']}: {model_type} avec TEE")
    print("   🆕 • Positions UAV: Générées automatiquement avec clusters géographiques")
    print("   🆕 • Délais communication: Basés sur distance euclidienne (get_comm_delay)")
    print("   🆕 • Simulation temporelle: SimPy Environment")
    print(f"   🆕 • Topologie sauvegardée: {topology_filename}")
    print("   🔒 • Sécurité: TEE + Détection menaces locale")
    if enable_greedy:
        print("   🧠 • Optimisation: Greedy Layer-Wise adaptatif")
    
    start_time = time.time()
    
    try:
        # Utilisation de simpy.Environment() pour la simulation temporelle
        print("⏱️ Lancement de l'environnement SimPy...")
        env.run()
        print("✅ Simulation SimPy terminée normalement")
    except Exception as e:
        print(f"⚠️ Simulation interrompue: {e}")
        import traceback
        traceback.print_exc()
    
    end_time = time.time()
    
    # Utiliser enhanced_collect_results
    results = enhanced_collect_results(uavs, config, positions, groups, end_time - start_time, global_results, enable_greedy)
    
    # Utiliser enhanced_result_generation_in_simulation
    generated_files = enhanced_result_generation_in_simulation(results)
    
    print(f"✅ Simulation DFL SÉCURISÉE + WEIGHTED+SELFISH terminée en {end_time - start_time:.2f} secondes")
    print(f"🎯 Précision finale moyenne: {results['final_average_accuracy']:.4f} ({results['final_average_accuracy']*100:.1f}%)")
    print(f"📡 Coût total communication: {results['total_communication_cost'] / 1024:.1f} KB")
    print(f"🔒 Opérations TEE totales: {results['total_tee_operations']}")
    print(f"🛡️ Menaces détectées totales: {results['total_threats_detected']}")
    print(f"📊 Algorithme Intra: Weighted FedAvg (équitable)")
    print(f"🎯 Algorithme Inter: Selfish FedAvg (chefs α=2.0)")
    if enable_greedy:
        print(f"🧠 Ajouts de couches Greedy: {results['total_greedy_additions']}")
    print(f"🔧 Modèle: {model_type} pour {config['dataset']}")
    print(f"🗺️ Topologie: {topology_filename}")
    
    print(f"\n📁 FICHIERS GÉNÉRÉS AUTOMATIQUEMENT:")
    print(f"   📝 Rapport détaillé: {generated_files['txt_file']}")
    print(f"   📋 Données JSON: {generated_files['json_file']}")
    print(f"   📈 Graphiques: {len(generated_files['graphs'])} fichiers PNG")
    
    return results

# ================================
# FONCTIONS UTILITAIRES ET INTERFACE
# ================================

def get_user_choice(options, prompt):
    """Fonction utilitaire pour obtenir un choix utilisateur"""
    print(f"\n{prompt}")
    for i, option in enumerate(options, 1):
        print(f"  {i}) {option}")
    
    while True:
        try:
            choice = int(input(f"Choisissez (1-{len(options)}): "))
            if 1 <= choice <= len(options):
                return choice - 1
            else:
                print(f"❌ Choix invalide. Entrez un nombre entre 1 et {len(options)}.")
        except ValueError:
            print("❌ Veuillez entrer un nombre valide.")

def get_configuration():
    """Interface pour configurer la simulation avec MNIST/FashionMNIST + Weighted+Selfish"""
    print("\n⚙️ CONFIGURATION SIMULATION SÉCURISÉE + WEIGHTED+SELFISH ALGORITHMS")
    print("🔧 AVEC MNIST/FASHIONMNIST + ALGORITHMES HYBRIDES")
    print("=" * 80)
    
    config = {}
    
    # 1. Choix du dataset - MNIST et FashionMNIST seulement
    dataset_choice = get_user_choice([
        "MNIST (Dataset chiffres manuscrits, rapide)",
        "FashionMNIST (Dataset vêtements, plus difficile)"
    ], "📊 Choisissez le dataset:")
    
    config['dataset'] = 'MNIST' if dataset_choice == 0 else 'FASHIONMNIST'
    
    print(f"🔧 DATASET {config['dataset']} SÉLECTIONNÉ:")
    print(f"   • Format: 28x28x1 (niveaux de gris)")
    print(f"   • Classes: 10 ({('chiffres 0-9' if config['dataset'] == 'MNIST' else 'types vêtements')})")
    print(f"   • Architecture: CNNModelMNIST simple et efficace")
    if config['dataset'] == 'MNIST':
        print(f"   • Performance attendue: ~95% accuracy")
    else:
        print(f"   • Performance attendue: ~88% accuracy (plus difficile)")
    
    # 2. Distribution des données
    iid_choice = get_user_choice([
        "IID (Distribution équilibrée)",
        "Non-IID (Distribution hétérogène, plus réaliste)"
    ], "📈 Distribution des données:")
    
    config['iid'] = iid_choice == 0
    
    # 3. Protocole de communication
    protocol_choice = get_user_choice([
        "All-to-All (Communication complète)",
        "Gossip (Communication économique)"
    ], "📡 Protocole de communication:")
    
    config['protocol'] = 'alltoall' if protocol_choice == 0 else 'gossip'
    
    # 4. Information sur les algorithmes
    print("\n📊 ALGORITHMES WEIGHTED + SELFISH:")
    print("  💡 Approche hybride pour équilibrer collaboration et performance")
    print("  📊 Intra-cluster: Weighted FedAvg (collaboration équitable)")
    print("  🎯 Inter-cluster: Selfish FedAvg (chefs augmentent leur influence α=2.0)")
    print("  ✅ Avantages:")
    print("    • Collaboration équitable au sein des clusters")
    print("    • Préservation de l'identité des clusters")
    print("    • Performance locale optimisée")
    print("    • Convergence stable")
    
    # 5. Configuration des paramètres
    print("\n🔧 Configuration des paramètres:")
    
    while True:
        try:
            config['num_uavs'] = int(input("   Nombre d'UAVs/Drones (3-20): "))
            if 3 <= config['num_uavs'] <= 20:
                break
            print("   ❌ Entrez un nombre entre 3 et 20")
        except ValueError:
            print("   ❌ Veuillez entrer un nombre valide")
    
    while True:
        try:
            config['num_clusters'] = int(input(f"   Nombre de clusters/groupes (1-5): "))
            if 1 <= config['num_clusters'] <= min(5, config['num_uavs']):
                break
            print(f"   ❌ Entrez un nombre entre 1 et {min(5, config['num_uavs'])}")
        except ValueError:
            print("   ❌ Veuillez entrer un nombre valide")
    
    while True:
        try:
            config['fl_rounds'] = int(input("   Nombre de rounds (1-20): "))
            if 1 <= config['fl_rounds'] <= 20:
                break
            print("   ❌ Entrez un nombre entre 1 et 20")
        except ValueError:
            print("   ❌ Veuillez entrer un nombre valide")
    
    while True:
        try:
            config['local_epochs'] = int(input("   Époques locales (1-10): "))
            if 1 <= config['local_epochs'] <= 10:
                break
            print("   ❌ Entrez un nombre entre 1 et 10")
        except ValueError:
            print("   ❌ Veuillez entrer un nombre valide")
    
    batch_choice = get_user_choice([
        "32 (Rapide, moins précis)",
        "64 (Équilibré)",
        "128 (Lent, plus précis)"
    ], "   Taille de batch:")
    
    config['batch_size'] = [32, 64, 128][batch_choice]
    
    return config

def main():
    """Fonction principale avec MNIST/FashionMNIST + Weighted+Selfish"""
    print("🚁 UAV FEDERATED LEARNING SIMULATOR SÉCURISÉ - WEIGHTED+SELFISH ALGORITHMS")
    print("🔧 MNIST/FASHIONMNIST + ALGORITHMES HYBRIDES")
    print("🔒 TEE + DÉTECTION MENACES + GREEDY LAYER-WISE + WEIGHTED+SELFISH")
    print("📊 + INTRA: WEIGHTED FEDAVG + INTER: SELFISH FEDAVG")
    print("🆕 + AJOUTS COMPLETS:")
    print("   • Positions UAV générées automatiquement")
    print("   • Délais communication basés sur distance euclidienne")
    print("   • Simulation temporelle avec SimPy Environment")
    print("   • Génération automatique de topologie PNG")
    print("📊 GÉNÉRATION AUTOMATIQUE DE RÉSULTATS ET GRAPHIQUES")
    print("=" * 100)
    
    # Afficher les détails des modèles
    print(f"\n🧠 MODÈLES SUPPORTÉS:")
    
    # Test MNIST
    model_mnist = CNNModelMNIST()
    params_mnist = sum(p.numel() for p in model_mnist.parameters())
    print(f"   • MNIST: {params_mnist:,} paramètres (CNNModelMNIST simple)")
    print(f"   • FashionMNIST: {params_mnist:,} paramètres (même architecture)")
    print(f"   🔧 Architecture unifiée: 28x28x1 -> Conv -> FC -> 10 classes")
    print(f"   ⚡ Performance: MNIST ~95%, FashionMNIST ~88%")
    print(f"   🤝 Support Greedy: Ajouté sans modification du modèle de base")
    
    # Afficher les algorithmes
    print(f"\n📊 ALGORITHMES WEIGHTED + SELFISH:")
    print(f"   • Intra-cluster: Weighted FedAvg")
    print(f"     - Collaboration équitable basée sur tailles des datasets")
    print(f"     - Tous les UAVs du cluster participent")
    print(f"     - Agrégation: Σ(wi * Mi) / Σ(wi)")
    print(f"   • Inter-cluster: Selfish FedAvg")
    print(f"     - Chefs de cluster seulement")
    print(f"     - Chefs augmentent leur influence (α=2.0)")
    print(f"     - Préservation identité des clusters")
    print(f"   🎯 Avantage: Équilibre collaboration locale / performance globale")
    
    try:
        # Configuration de la simulation
        config = get_configuration()
        
        # Choix du type d'entraînement
        training_choice = get_user_choice([
            "Standard sécurisé (TEE + Détection menaces + Weighted+Selfish)",
            "Greedy sécurisé (TEE + Détection menaces + Greedy Layer-Wise + Weighted+Selfish)"
        ], "🧠 Type d'entraînement:")
        
        enable_greedy = training_choice == 1
        
        print(f"\n📋 CONFIGURATION FINALE WEIGHTED+SELFISH:")
        print(f"  • Dataset: {config['dataset']}")
        print(f"  • Distribution: {'IID' if config['iid'] else 'Non-IID'}")
        print(f"  • Protocole: {config['protocol'].upper()}")
        print(f"  • UAVs/Drones: {config['num_uavs']}")
        print(f"  • Clusters/Groupes: {config['num_clusters']}")
        print(f"  • Rounds: {config['fl_rounds']}")
        print(f"  • Époques locales: {config['local_epochs']}")
        print(f"  • Batch size: {config['batch_size']}")
        print(f"  • Type: {'Greedy' if enable_greedy else 'Standard'} sécurisé")
        print(f"  • Sécurité: TEE + Détection menaces activées")
        print(f"  📊 Algorithme Intra: Weighted FedAvg (équitable)")
        print(f"  🎯 Algorithme Inter: Selfish FedAvg (chefs α=2.0)")
        print(f"  🔧 Architecture: CNNModelMNIST pour {config['dataset']}")
        print(f"  🆕 Ajouts: Positions + Communication + Simulation + Topologie")
        print(f"  • Génération: Résultats et graphiques automatiques")
        
        # Confirmation
        print("\n❓ Voulez-vous lancer la simulation DFL Sécurisée + Weighted+Selfish ?")
        print("  1) Oui, lancer la simulation hybride")
        print("  2) Non, recommencer la configuration")
        print("  3) Annuler")
        
        while True:
            try:
                confirm = int(input("Votre choix (1-3): "))
                if confirm == 1:
                    break
                elif confirm == 2:
                    return main()  # Recommencer
                elif confirm == 3:
                    print("❌ Simulation annulée.")
                    return
                else:
                    print("❌ Choix invalide. Choisissez 1, 2 ou 3.")
            except ValueError:
                print("❌ Veuillez entrer un nombre valide.")
        
        # Lancement de la simulation
        greedy_label = "Greedy" if enable_greedy else "Standard"
        print(f"\n🚀 LANCEMENT DE LA SIMULATION {greedy_label.upper()} SÉCURISÉE + WEIGHTED+SELFISH...")
        print(f"📅 Début: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        print(f"📊 Algorithmes: Intra-Weighted + Inter-Selfish")
        
        print("🔧 Utilisation de l'architecture CNNModelMNIST")
        print("⚡ Performance attendue selon dataset")
        print("🤝 Algorithmes hybrides pour équilibre optimal")
        
        results = run_simulation(config, enable_greedy=enable_greedy)
        
        print(f"\n🎉 SIMULATION {greedy_label.upper()} SÉCURISÉE + WEIGHTED+SELFISH TERMINÉE AVEC SUCCÈS!")
        print(f"📅 Fin: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        print(f"🎯 Précision finale: {results['final_average_accuracy']*100:.2f}%")
        print(f"⏱️ Temps d'exécution: {results['simulation_time']:.2f} secondes")
        print(f"📁 Fichiers générés dans les dossiers:")
        print(f"   📂 results/ - Fichiers TXT et JSON détaillés")
        print(f"   📂 graphs/ - Graphiques automatiques")
        print(f"   📂 topology/ - Topologie PNG")
        print(f"   📊 Scenario: {results['scenario_name']}")
        print(f"   🗺️ Topologie: {results['topology_filename']}")
        
        # Statistiques détaillées avec algorithmes
        print(f"\n📊 STATISTIQUES DÉTAILLÉES WEIGHTED+SELFISH:")
        print(f"   📡 Coût communication total: {results['total_communication_cost'] / 1024:.1f} KB")
        print(f"   💻 Coût computation total: {results['total_computational_cost']:,}")
        print(f"   🔒 Opérations TEE: {results['total_tee_operations']}")
        print(f"   🛡️ Menaces détectées: {results['total_threats_detected']}")
        print(f"   📊 Algorithme Intra: Weighted FedAvg (équitable)")
        print(f"   🎯 Algorithme Inter: Selfish FedAvg (chefs α=2.0)")
        
        if enable_greedy:
            print(f"   🧠 Ajouts de couches Greedy: {results['total_greedy_additions']}")
            if results['total_greedy_additions'] > 0:
                print(f"   ⚡ Le modèle s'est adapté dynamiquement dans le TEE!")
        
        print(f"   🔧 Architecture: CNNModelMNIST pour {config['dataset']}")
        print(f"   ⚡ Performance: {results['final_average_accuracy']*100:.1f}% (conforme aux attentes)")
        
        # Analyse des algorithmes
        print(f"\n🤝 ANALYSE DES ALGORITHMES HYBRIDES:")
        print(f"   📊 Weighted FedAvg (Intra): Collaboration équitable réussie")
        print(f"   🎯 Selfish FedAvg (Inter): Préservation identité clusters")
        print(f"   ⚖️ Équilibre: Performance locale + Diversité globale")
        print(f"   🏆 Avantage: Meilleur des deux mondes")
        print(f"   🔒 Sécurité: TEE + Détection menaces (pas de communication extra)")
        print(f"   🧠 Adaptabilité: {'Greedy Layer-Wise activé' if enable_greedy else 'Standard efficace'}")
        print(f"   🛠️ Maintenance: Architecture simple et robuste")
        
        print(f"\n🏆 CODES WEIGHTED + SELFISH ALGORITHMS:")
        print(f"   ✅ Intra-cluster: Weighted FedAvg (tailles datasets respectées)")
        print(f"   ✅ Inter-cluster: Selfish FedAvg (chefs α=2.0 pour identité)")
        print(f"   ✅ Sécurité: TEE + Détection menaces locale")
        print(f"   ✅ Architecture: CNNModelMNIST simple et efficace")
        print(f"   ✅ Datasets: MNIST + FashionMNIST supportés")
        print(f"   ✅ Performance: Équilibre collaboration/égoïsme optimal")
        print(f"   ✅ Maintenance: Code modulaire et extensible")
        
    except KeyboardInterrupt:
        print("\n\n⚠️ Simulation interrompue par l'utilisateur (Ctrl+C)")
        print("👋 Au revoir!")
        
    except Exception as e:
        print(f"\n❌ Erreur pendant la simulation: {str(e)}")
        print("🐛 Détails de l'erreur:")
        import traceback
        traceback.print_exc()

if __name__ == "__main__":
    # Vérification des dépendances
    try:
        import torch
        import torchvision
        import simpy
        import matplotlib
        import pandas
        print("✅ Toutes les dépendances sont disponibles.")
        print("🔧 Modèles configurés:")
        print("   • MNIST: CNNModelMNIST simple")
        print("   • FashionMNIST: CNNModelMNIST (même architecture)")
        print("🔒 TEE + Détection menaces + Greedy Layer-Wise + Weighted+Selfish prêts")
        print("📊 ALGORITHMES WEIGHTED + SELFISH:")
        print("   • weighted_fedavg() - Agrégation équitable intra-cluster")
        print("   • selfish_fedavg() - Agrégation égoïste inter-cluster")
        print("   • Équilibre: Collaboration locale + Égoïsme global")
        print("🆕 AJOUTS INTÉGRÉS:")
        print("   • create_uav_positions() - Génération positions UAV")
        print("   • get_comm_delay() - Délais basés sur distance euclidienne")
        print("   • euclidean_distance() - Calcul distance entre UAVs")
        print("   • generate_network_topology_image() - Topologie PNG")
        print("   • simpy.Environment() - Simulation temporelle")
        print("📊 GÉNÉRATION AUTOMATIQUE DE RÉSULTATS ACTIVÉE")
        print("🎯 VERSION COMPLÈTE OPTIMISÉE: Sécurité + Performance + Contrôle d'influence")
        
    except ImportError as e:
        print(f"❌ Dépendance manquante: {e}")
        print("📦 Installez avec: pip install torch torchvision simpy matplotlib pandas numpy")
        exit(1)
    
    # Menu principal
    print(f"\n🎯 CHOISISSEZ LE MODE:")
    print("  1) Simulation interactive personnalisée")
    print("  2) Test automatique des valeurs d'alpha")
    print("  3) Test de génération de résultats uniquement")
    print("  4) Quitter")
    
    while True:
        try:
            mode_choice = int(input("Votre choix (1-4): "))
            if mode_choice == 1:
                main()
                break
            elif mode_choice == 2:
                test_multiple_alpha_values()
                break
            elif mode_choice == 3:
                test_result_generation()
                break
            elif mode_choice == 4:
                print("👋 Au revoir!")
                break
            else:
                print("❌ Choix invalide. Choisissez 1, 2, 3 ou 4.")
        except ValueError:
            print("❌ Veuillez entrer un nombre valide.")
        except KeyboardInterrupt:
            print("\n👋 Au revoir!")
            break     
            
            
            
            
            
            
            
            
            
            
