# config_loader.py

from kubernetes import client, config

config.load_kube_config()

v1 = client.CoreV1Api()
apps_v1 = client.AppsV1Api()
rback_v1 = client.RbacAuthorizationV1Api()
networking_v1 = client.NetworkingV1Api()
