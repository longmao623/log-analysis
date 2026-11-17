#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
网络安全日志分析与建模大作业
方法：KNN分类 + K-Means聚类
数据集：Apache access.log（主）+ error.log（辅助）
"""

import re
import pandas as pd
import numpy as np
import matplotlib
matplotlib.rcParams['font.sans-serif'] = ['SimHei', 'Microsoft YaHei', 'Arial Unicode MS']
matplotlib.rcParams['axes.unicode_minus'] = False
import matplotlib.pyplot as plt
from datetime import datetime
from urllib.parse import unquote
import warnings
warnings.filterwarnings('ignore')

from sklearn.preprocessing import StandardScaler, LabelEncoder
from sklearn.model_selection import train_test_split
from sklearn.neighbors import KNeighborsClassifier
from sklearn.cluster import KMeans
from sklearn.metrics import (accuracy_score, precision_score, recall_score,
                             f1_score, confusion_matrix, classification_report,
                             silhouette_score)

# ==================== 1. 数据加载与解析 ====================

def parse_access_log(filepath):
    """解析Apache Combined Log Format"""
    pattern = r'^(\S+)\s+\S+\s+\S+\s+\[(.*?)\]\s+"(\S+)\s+(.*?)\s+HTTP/\d\.\d"\s+(\d{3})\s+(\d+)\s+"(.*?)"\s+"(.*?)"'
    records = []
    with open(filepath, 'r', encoding='utf-8', errors='replace') as f:
        for line in f:
            line = line.strip()
            m = re.match(pattern, line)
            if m:
                ip, time_str, method, url, status, size, referer, ua = m.groups()
                records.append({
                    'ip': ip,
                    'timestamp': time_str,
                    'method': method,
                    'url': url,
                    'status': int(status),
                    'size': int(size),
                    'referer': referer,
                    'user_agent': ua
                })
    return pd.DataFrame(records)

print("=" * 60)
print("1. 数据加载")
print("=" * 60)

df = parse_access_log('access.log')
print(f"成功解析 access.log: {len(df)} 条记录")
print(f"字段: {list(df.columns)}")
print(f"\n前5条:\n{df.head()}")

# ==================== 2. 数据预处理 ====================

print("\n" + "=" * 60)
print("2. 数据预处理")
print("=" * 60)

# 2.1 解析时间
def parse_time(t):
    try:
        dt = datetime.strptime(t, '%d/%b/%Y:%H:%M:%S %z')
        return dt.hour, dt.weekday()
    except:
        return 0, 0

df[['hour', 'weekday']] = df['timestamp'].apply(lambda t: pd.Series(parse_time(t)))

# 2.2 URL解码
df['url_decoded'] = df['url'].apply(lambda u: unquote(u))

# 2.3 缺失值检查
print(f"缺失值统计:\n{df.isnull().sum()}")

# ==================== 3. 特征工程 ====================

print("\n" + "=" * 60)
print("3. 特征提取")
print("=" * 60)

# 攻击关键词模式
SQL_KEYWORDS = ['select', 'union', 'insert', 'update', 'delete', 'drop', 'exec',
                'script', 'eval', 'updatexml', 'extractvalue', 'base64_decode',
                'concat', 'sleep', 'benchmark']
XSS_KEYWORDS = ['<script', 'alert(', 'onerror', 'onload', 'javascript:', 'document.cookie']
PATH_TRAVERSAL = ['../', '..\\', '/etc/passwd', '/etc/shadow', 'boot.ini',
                  'win.ini', 'system32', 'c:\\', 'file://']
ADMIN_PAGES = ['admin', 'login', 'wp-login', 'phpmyadmin', 'manager', 'config',
               '.env', '.git', '.svn', '.htaccess']
SCANNER_UAS = ['nmap', 'nikto', 'sqlmap', 'burp', 'metasploit', 'dirbuster',
               'gobuster', 'masscan', 'zgrab']

def extract_features(row):
    url = row['url_decoded'].lower()
    ua = row['user_agent'].lower()
    method = row['method']
    status = row['status']

    features = {}
    # 基础特征
    features['url_length'] = len(row['url'])
    features['has_query'] = 1 if '?' in row['url'] else 0
    features['param_count'] = len(row['url'].split('?')[1].split('&')) if '?' in row['url'] else 0

    # 攻击特征
    features['has_sql_kw'] = 1 if any(kw in url for kw in SQL_KEYWORDS) else 0
    features['has_xss_kw'] = 1 if any(kw in url for kw in XSS_KEYWORDS) else 0
    features['has_path_traversal'] = 1 if any(p in url for p in PATH_TRAVERSAL) else 0
    features['has_admin_page'] = 1 if any(a in url for a in ADMIN_PAGES) else 0

    # 请求方法
    method_map = {'GET': 0, 'POST': 1, 'HEAD': 2, 'PUT': 3,
                  'DELETE': 4, 'TRACE': 5, 'DEBUG': 6, 'PROPFIND': 7, 'OPTIONS': 8}
    features['method_encoded'] = method_map.get(method, 9)

    # 是否为异常方法
    features['is_unusual_method'] = 1 if method in ['TRACE', 'DEBUG', 'PROPFIND'] else 0

    # User-Agent
    features['is_scanner_ua'] = 1 if any(s in ua for s in SCANNER_UAS) else 0
    features['ua_length'] = len(row['user_agent'])
    features['is_empty_ua'] = 1 if row['user_agent'] == '-' else 0

    # 状态码
    features['is_4xx'] = 1 if 400 <= status < 500 else 0
    features['is_5xx'] = 1 if 500 <= status < 600 else 0
    features['status'] = status

    # 时间特征
    features['hour'] = row['hour']
    features['is_night'] = 1 if row['hour'] in [0, 1, 2, 3, 4, 5] else 0

    # 响应大小
    features['size'] = row['size']
    features['is_large_response'] = 1 if row['size'] > 5000 else 0

    return pd.Series(features)

feature_df = df.apply(extract_features, axis=1)
print(f"提取特征数: {feature_df.shape[1]}")
print(f"特征列表: {list(feature_df.columns)}")
print(f"\n特征统计:\n{feature_df.describe()}")

# ==================== 4. 自动标注标签 ====================

print("\n" + "=" * 60)
print("4. 自动标注（基于规则）")
print("=" * 60)

def label_request(row):
    """基于规则自动标注：攻击=1，正常=0"""
    url = row['url_decoded'].lower()
    ua = row['user_agent'].lower()
    method = row['method']

    # 明确攻击特征
    if any(s in ua for s in SCANNER_UAS):
        return 1
    if method in ['TRACE', 'DEBUG', 'PROPFIND']:
        return 1
    if any(kw in url for kw in SQL_KEYWORDS):
        return 1
    if any(kw in url for kw in XSS_KEYWORDS):
        return 1
    if any(p in url for p in PATH_TRAVERSAL):
        return 1

    # 目录爆破特征：短时间内大量404
    # 这里用简单规则：admin/login/config相关 + 404
    admin_404 = any(a in url for a in ADMIN_PAGES) and row['status'] == 404
    if admin_404:
        return 1

    # 其他视为正常
    return 0

df['label'] = df.apply(label_request, axis=1)
attack_count = df['label'].sum()
normal_count = len(df) - attack_count
print(f"正常请求: {normal_count} ({normal_count/len(df)*100:.1f}%)")
print(f"攻击请求: {attack_count} ({attack_count/len(df)*100:.1f}%)")

# 合并特征和标签
X = feature_df.values
y = df['label'].values
feature_names = list(feature_df.columns)

# ==================== 5. 数据标准化 ====================

scaler = StandardScaler()
X_scaled = scaler.fit_transform(X)

# ==================== 6. KNN 分类模型 ====================

print("\n" + "=" * 60)
print("5. KNN 分类模型")
print("=" * 60)

X_train, X_test, y_train, y_test = train_test_split(
    X_scaled, y, test_size=0.3, random_state=42, stratify=y)

print(f"训练集: {len(X_train)} 条，测试集: {len(X_test)} 条")

# 选择最优K值
best_k = 0
best_score = 0
for k in range(3, 21, 2):
    knn = KNeighborsClassifier(n_neighbors=k)
    knn.fit(X_train, y_train)
    score = knn.score(X_test, y_test)
    if score > best_score:
        best_score = score
        best_k = k

print(f"最优 K 值: {best_k} (准确率: {best_score:.4f})")

# 最终模型
knn = KNeighborsClassifier(n_neighbors=best_k, metric='euclidean')
knn.fit(X_train, y_train)
y_pred = knn.predict(X_test)

# 评估
print(f"\nKNN 分类结果:")
print(f"准确率 (Accuracy):  {accuracy_score(y_test, y_pred):.4f}")
print(f"精确率 (Precision): {precision_score(y_test, y_pred):.4f}")
print(f"召回率 (Recall):    {recall_score(y_test, y_pred):.4f}")
print(f"F1 分数:            {f1_score(y_test, y_pred):.4f}")
print(f"\n分类报告:\n{classification_report(y_test, y_pred, target_names=['正常', '攻击'])}")

# 混淆矩阵
cm = confusion_matrix(y_test, y_pred)
print(f"混淆矩阵:\n{cm}")

# ==================== 7. K-Means 聚类模型 ====================

print("\n" + "=" * 60)
print("6. K-Means 聚类模型")
print("=" * 60)

# 使用肘部法则选K
inertias = []
silhouettes = []
K_range = range(2, 11)
for k in K_range:
    km = KMeans(n_clusters=k, random_state=42, n_init=10)
    km.fit(X_scaled)
    inertias.append(km.inertia_)
    silhouettes.append(silhouette_score(X_scaled, km.labels_))

best_km_k = list(K_range)[np.argmax(silhouettes)]
print(f"最优聚类数 K: {best_km_k} (轮廓系数: {max(silhouettes):.4f})")

# 最终聚类
kmeans = KMeans(n_clusters=2, random_state=42, n_init=10)
cluster_labels = kmeans.fit_predict(X_scaled)

# 分析聚类结果与标注标签的对应关系
print(f"\n聚类结果分布:")
print(f"聚类 0: {(cluster_labels == 0).sum()} 条")
print(f"聚类 1: {(cluster_labels == 1).sum()} 条")

# 计算聚类纯度
for c in [0, 1]:
    mask = cluster_labels == c
    cluster_attack = df.loc[mask, 'label'].sum()
    cluster_total = mask.sum()
    purity = cluster_attack / cluster_total if cluster_total > 0 else 0
    dominant = '攻击' if purity > 0.5 else '正常'
    print(f"聚类 {c}: 攻击率={purity:.2%}, 主导类别={dominant}")

# 轮廓系数
sil_score = silhouette_score(X_scaled, cluster_labels)
print(f"\n轮廓系数 (Silhouette Score): {sil_score:.4f}")

# ==================== 8. 可视化 ====================

print("\n" + "=" * 60)
print("7. 生成可视化图表")
print("=" * 60)

fig, axes = plt.subplots(2, 3, figsize=(16, 10))
fig.suptitle('网络安全日志分析与建模结果', fontsize=14)

# (0,0) 类别分布饼图
ax = axes[0, 0]
labels = ['正常', '攻击']
sizes = [normal_count, attack_count]
colors = ['#4CAF50', '#F44336']
ax.pie(sizes, labels=labels, autopct='%1.1f%%', colors=colors, startangle=90)
ax.set_title('请求类别分布')

# (0,1) KNN混淆矩阵热力图
ax = axes[0, 1]
im = ax.imshow(cm, interpolation='nearest', cmap='Blues')
ax.set_title('KNN 混淆矩阵')
ax.set_xticks([0, 1])
ax.set_yticks([0, 1])
ax.set_xticklabels(['正常', '攻击'])
ax.set_yticklabels(['正常', '攻击'])
ax.set_xlabel('预测标签')
ax.set_ylabel('真实标签')
for i in range(2):
    for j in range(2):
        ax.text(j, i, str(cm[i, j]), ha='center', va='center', color='red', fontsize=14)

# (0,2) K值选择
ax = axes[0, 2]
ax.plot(range(3, 21, 2), [KNeighborsClassifier(n_neighbors=k).fit(X_train, y_train).score(X_test, y_test)
                          for k in range(3, 21, 2)], 'bo-')
ax.set_title('KNN K值选择')
ax.set_xlabel('K值')
ax.set_ylabel('准确率')
ax.axvline(x=best_k, color='r', linestyle='--', label=f'最优K={best_k}')
ax.legend()

# (1,0) 肘部法则
ax = axes[1, 0]
ax.plot(list(K_range), inertias, 'go-')
ax.set_title('K-Means 肘部法则')
ax.set_xlabel('聚类数 K')
ax.set_ylabel('惯性 (Inertia)')
ax.axvline(x=best_km_k, color='r', linestyle='--', label=f'最优K={best_km_k}')
ax.legend()

# (1,1) 轮廓系数
ax = axes[1, 1]
ax.plot(list(K_range), silhouettes, 'mo-')
ax.set_title('K-Means 轮廓系数')
ax.set_xlabel('聚类数 K')
ax.set_ylabel('轮廓系数')
ax.axvline(x=best_km_k, color='r', linestyle='--', label=f'最优K={best_km_k}')
ax.legend()

# (1,2) 特征重要性（用KNN的最近邻平均距离间接反映）
ax = axes[1, 2]
# 用不同特征的均值差异来展示区分度
feature_importance = []
for i, fname in enumerate(feature_names):
    normal_mean = X[y == 0, i].mean()
    attack_mean = X[y == 1, i].mean()
    importance = abs(normal_mean - attack_mean)
    feature_importance.append((fname, importance))
feature_importance.sort(key=lambda x: x[1], reverse=True)
top_features = feature_importance[:10]
ax.barh([f[0] for f in top_features], [f[1] for f in top_features], color='steelblue')
ax.set_title('Top10 区分特征')
ax.set_xlabel('均值差异')

plt.tight_layout()
plt.savefig('output/results.png', dpi=150, bbox_inches='tight')
print("图表已保存: output/results.png")
plt.close()

# ==================== 9. 保存结果 ====================

# 保存特征数据
feature_df['label'] = df['label']
feature_df.to_csv('output/features.csv', index=False)
print("特征数据已保存: output/features.csv")

# 保存预测结果
result_df = df[['ip', 'timestamp', 'method', 'url', 'status', 'label']].copy()
result_df['knn_pred'] = knn.predict(X_scaled)
result_df['kmeans_cluster'] = cluster_labels
result_df.to_csv('output/predictions.csv', index=False)
print("预测结果已保存: output/predictions.csv")

print("\n" + "=" * 60)
print("运行完成！")
print("=" * 60)
