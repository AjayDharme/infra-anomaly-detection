import json

def analyze_resource(resource):
    cpu_avg = resource["cpu_avg"]
    cpu_p95 = resource["cpu_p95"]
    memory = resource["memory_avg"]
    network = resource["network_pct"]
    internet = resource["internet_facing"]
    identity = resource["identity_attached"]

    result = {
        "resource_id": resource["resource_id"],
        "is_anomalous": False,
        "anomaly_type": None,
        "reason": "",
        "suggested_action": "",
        "confidence": 0.0,
        "security_note": None
    }

    confidence = 0.5

    # Rule 1: Over-provisioned
    if cpu_avg < 10 and memory > 60:
        result["is_anomalous"] = True
        result["anomaly_type"] = "over_provisioned"
        result["reason"] = "Low CPU usage but high memory allocation indicates inefficient utilization"
        result["suggested_action"] = "Downsize instance or optimize memory usage"
        confidence += 0.2

    # Rule 2: Under-provisioned
    elif cpu_avg > 80 and cpu_p95 > 95:
        result["is_anomalous"] = True
        result["anomaly_type"] = "under_provisioned"
        result["reason"] = "CPU usage consistently high with peak saturation"
        result["suggested_action"] = "Scale up instance or add auto-scaling"
        confidence += 0.25

    # Rule 3: Imbalanced usage
    elif cpu_avg > 70 and memory < 50:
        result["is_anomalous"] = True
        result["anomaly_type"] = "imbalanced_usage"
        result["reason"] = "High CPU usage but low memory usage suggests workload imbalance"
        result["suggested_action"] = "Analyze workload distribution or optimize compute tasks"
        confidence += 0.15

    # Security check
    if internet and identity:
        result["security_note"] = "Internet-facing resource with attached identity increases attack surface"

    result["confidence"] = round(min(confidence, 1.0), 2)

    return result


# Sample Data (extended)
data = [
    {
        "resource_id": "i-1",
        "cpu_avg": 2,
        "cpu_p95": 5,
        "memory_avg": 70,
        "network_pct": 10,
        "internet_facing": True,
        "identity_attached": True
    },
    {
        "resource_id": "i-2",
        "cpu_avg": 85,
        "cpu_p95": 98,
        "memory_avg": 40,
        "network_pct": 60,
        "internet_facing": False,
        "identity_attached": False
    },
    {
        "resource_id": "i-3",
        "cpu_avg": 75,
        "cpu_p95": 80,
        "memory_avg": 30,
        "network_pct": 20,
        "internet_facing": False,
        "identity_attached": True
    },
    {
        "resource_id": "i-4",
        "cpu_avg": 15,
        "cpu_p95": 25,
        "memory_avg": 20,
        "network_pct": 5,
        "internet_facing": False,
        "identity_attached": False
    },
    {
        "resource_id": "i-5",
        "cpu_avg": 90,
        "cpu_p95": 99,
        "memory_avg": 85,
        "network_pct": 80,
        "internet_facing": True,
        "identity_attached": True
    }
]

results = [analyze_resource(r) for r in data]

print(json.dumps(results, indent=2))