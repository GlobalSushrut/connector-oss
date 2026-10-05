# Connector Terraform Variables
# Separate file for variable definitions with detailed descriptions

# =============================================================================
# Environment
# =============================================================================

variable "environment" {
  description = "Environment name (dev, staging, prod)"
  type        = string
  default     = "dev"

  validation {
    condition     = contains(["dev", "staging", "prod"], var.environment)
    error_message = "Environment must be dev, staging, or prod."
  }
}

variable "region" {
  description = "AWS region for deployment"
  type        = string
  default     = "us-east-1"
}

variable "cluster_name" {
  description = "Name of the EKS cluster"
  type        = string
  default     = "connector-cluster"
}

# =============================================================================
# Compute
# =============================================================================

variable "node_count" {
  description = "Number of Connector worker nodes"
  type        = number
  default     = 3

  validation {
    condition     = var.node_count >= 1 && var.node_count <= 100
    error_message = "Node count must be between 1 and 100."
  }
}

variable "instance_type" {
  description = "EC2 instance type for worker nodes"
  type        = string
  default     = "m6i.xlarge"
}

variable "connector_version" {
  description = "Connector container image version/tag"
  type        = string
  default     = "latest"
}

# =============================================================================
# GPU (Optional)
# =============================================================================

variable "enable_gpu" {
  description = "Enable GPU nodes for LLM inference acceleration"
  type        = bool
  default     = false
}

variable "gpu_instance_type" {
  description = "GPU instance type (g5.xlarge, p4d.24xlarge, etc.)"
  type        = string
  default     = "g5.xlarge"
}

variable "gpu_node_count" {
  description = "Number of GPU nodes"
  type        = number
  default     = 0
}

# =============================================================================
# Resource Limits
# =============================================================================

variable "cpu_limit" {
  description = "CPU limit per Connector pod (Kubernetes format)"
  type        = string
  default     = "4"
}

variable "cpu_request" {
  description = "CPU request per Connector pod"
  type        = string
  default     = "2"
}

variable "memory_limit" {
  description = "Memory limit per Connector pod"
  type        = string
  default     = "8Gi"
}

variable "memory_request" {
  description = "Memory request per Connector pod"
  type        = string
  default     = "4Gi"
}

variable "storage_size" {
  description = "Persistent storage size per node"
  type        = string
  default     = "100Gi"
}

# =============================================================================
# Networking
# =============================================================================

variable "vpc_cidr" {
  description = "CIDR block for the VPC"
  type        = string
  default     = "10.0.0.0/16"
}

variable "enable_private_endpoint" {
  description = "Enable private API endpoint (disable public access)"
  type        = bool
  default     = true
}

# =============================================================================
# Security
# =============================================================================

variable "kms_key_arn" {
  description = "ARN of KMS key for encryption (leave empty to use AWS managed)"
  type        = string
  default     = ""
}

variable "enable_secrets_manager" {
  description = "Use AWS Secrets Manager for secret storage"
  type        = bool
  default     = true
}

# =============================================================================
# Observability
# =============================================================================

variable "enable_cloudwatch" {
  description = "Enable CloudWatch logging and metrics"
  type        = bool
  default     = true
}

variable "log_retention_days" {
  description = "CloudWatch log retention period in days"
  type        = number
  default     = 30

  validation {
    condition     = contains([1, 3, 5, 7, 14, 30, 60, 90, 120, 150, 180, 365, 400, 545, 731, 1827, 3653], var.log_retention_days)
    error_message = "Log retention must be a valid CloudWatch retention period."
  }
}
