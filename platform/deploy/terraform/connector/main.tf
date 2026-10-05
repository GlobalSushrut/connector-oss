# Connector Terraform Module
# Deploys Connector AI runtime to cloud infrastructure

terraform {
  required_version = ">= 1.0.0"

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = ">= 5.0"
    }
    kubernetes = {
      source  = "hashicorp/kubernetes"
      version = ">= 2.20"
    }
  }
}

# =============================================================================
# Variables
# =============================================================================

variable "environment" {
  description = "Environment name (dev, staging, prod)"
  type        = string
  default     = "dev"
}

variable "region" {
  description = "AWS region"
  type        = string
  default     = "us-east-1"
}

variable "cluster_name" {
  description = "EKS cluster name"
  type        = string
  default     = "connector-cluster"
}

variable "node_count" {
  description = "Number of Connector nodes"
  type        = number
  default     = 3
}

variable "instance_type" {
  description = "EC2 instance type for nodes"
  type        = string
  default     = "m6i.xlarge"
}

variable "connector_version" {
  description = "Connector image version"
  type        = string
  default     = "latest"
}

variable "enable_gpu" {
  description = "Enable GPU nodes for LLM inference"
  type        = bool
  default     = false
}

variable "gpu_instance_type" {
  description = "GPU instance type"
  type        = string
  default     = "g5.xlarge"
}

variable "gpu_node_count" {
  description = "Number of GPU nodes"
  type        = number
  default     = 0
}

# Resource limits
variable "cpu_limit" {
  description = "CPU limit per Connector pod"
  type        = string
  default     = "4"
}

variable "memory_limit" {
  description = "Memory limit per Connector pod"
  type        = string
  default     = "8Gi"
}

variable "storage_size" {
  description = "Persistent storage size"
  type        = string
  default     = "100Gi"
}

# Networking
variable "vpc_cidr" {
  description = "VPC CIDR block"
  type        = string
  default     = "10.0.0.0/16"
}

variable "enable_private_endpoint" {
  description = "Enable private API endpoint"
  type        = bool
  default     = true
}

# Security
variable "kms_key_arn" {
  description = "KMS key ARN for encryption"
  type        = string
  default     = ""
}

variable "enable_secrets_manager" {
  description = "Use AWS Secrets Manager"
  type        = bool
  default     = true
}

# Observability
variable "enable_cloudwatch" {
  description = "Enable CloudWatch logging"
  type        = bool
  default     = true
}

variable "log_retention_days" {
  description = "CloudWatch log retention in days"
  type        = number
  default     = 30
}

# =============================================================================
# Locals
# =============================================================================

locals {
  common_tags = {
    Environment = var.environment
    Project     = "connector"
    ManagedBy   = "terraform"
  }

  name_prefix = "connector-${var.environment}"
}

# =============================================================================
# VPC
# =============================================================================

module "vpc" {
  source  = "terraform-aws-modules/vpc/aws"
  version = "~> 5.0"

  name = "${local.name_prefix}-vpc"
  cidr = var.vpc_cidr

  azs             = ["${var.region}a", "${var.region}b", "${var.region}c"]
  private_subnets = [cidrsubnet(var.vpc_cidr, 4, 0), cidrsubnet(var.vpc_cidr, 4, 1), cidrsubnet(var.vpc_cidr, 4, 2)]
  public_subnets  = [cidrsubnet(var.vpc_cidr, 4, 3), cidrsubnet(var.vpc_cidr, 4, 4), cidrsubnet(var.vpc_cidr, 4, 5)]

  enable_nat_gateway   = true
  single_nat_gateway   = var.environment != "prod"
  enable_dns_hostnames = true
  enable_dns_support   = true

  public_subnet_tags = {
    "kubernetes.io/role/elb" = 1
  }

  private_subnet_tags = {
    "kubernetes.io/role/internal-elb" = 1
  }

  tags = local.common_tags
}

# =============================================================================
# EKS Cluster
# =============================================================================

module "eks" {
  source  = "terraform-aws-modules/eks/aws"
  version = "~> 19.0"

  cluster_name    = var.cluster_name
  cluster_version = "1.28"

  vpc_id     = module.vpc.vpc_id
  subnet_ids = module.vpc.private_subnets

  cluster_endpoint_public_access  = !var.enable_private_endpoint
  cluster_endpoint_private_access = var.enable_private_endpoint

  # Encryption
  cluster_encryption_config = var.kms_key_arn != "" ? {
    provider_key_arn = var.kms_key_arn
    resources        = ["secrets"]
  } : {}

  # Managed node groups
  eks_managed_node_groups = {
    connector = {
      name           = "${local.name_prefix}-nodes"
      instance_types = [var.instance_type]
      
      min_size     = var.node_count
      max_size     = var.node_count * 2
      desired_size = var.node_count

      labels = {
        role = "connector"
      }

      tags = local.common_tags
    }
  }

  tags = local.common_tags
}

# GPU node group (optional)
resource "aws_eks_node_group" "gpu" {
  count = var.enable_gpu && var.gpu_node_count > 0 ? 1 : 0

  cluster_name    = module.eks.cluster_name
  node_group_name = "${local.name_prefix}-gpu-nodes"
  node_role_arn   = module.eks.eks_managed_node_groups["connector"].iam_role_arn
  subnet_ids      = module.vpc.private_subnets

  instance_types = [var.gpu_instance_type]

  scaling_config {
    desired_size = var.gpu_node_count
    max_size     = var.gpu_node_count * 2
    min_size     = var.gpu_node_count
  }

  labels = {
    role        = "connector-gpu"
    "nvidia.com/gpu" = "true"
  }

  taint {
    key    = "nvidia.com/gpu"
    value  = "true"
    effect = "NO_SCHEDULE"
  }

  tags = local.common_tags
}

# =============================================================================
# Storage
# =============================================================================

resource "aws_efs_file_system" "connector" {
  creation_token = "${local.name_prefix}-efs"
  encrypted      = true
  kms_key_id     = var.kms_key_arn != "" ? var.kms_key_arn : null

  lifecycle_policy {
    transition_to_ia = "AFTER_30_DAYS"
  }

  tags = merge(local.common_tags, {
    Name = "${local.name_prefix}-efs"
  })
}

resource "aws_efs_mount_target" "connector" {
  count = length(module.vpc.private_subnets)

  file_system_id  = aws_efs_file_system.connector.id
  subnet_id       = module.vpc.private_subnets[count.index]
  security_groups = [aws_security_group.efs.id]
}

resource "aws_security_group" "efs" {
  name        = "${local.name_prefix}-efs-sg"
  description = "EFS security group"
  vpc_id      = module.vpc.vpc_id

  ingress {
    from_port       = 2049
    to_port         = 2049
    protocol        = "tcp"
    security_groups = [module.eks.cluster_security_group_id]
  }

  tags = local.common_tags
}

# =============================================================================
# Secrets Manager
# =============================================================================

resource "aws_secretsmanager_secret" "connector" {
  count = var.enable_secrets_manager ? 1 : 0

  name        = "${local.name_prefix}/config"
  description = "Connector configuration secrets"
  kms_key_id  = var.kms_key_arn != "" ? var.kms_key_arn : null

  tags = local.common_tags
}

resource "aws_secretsmanager_secret" "llm_api_key" {
  count = var.enable_secrets_manager ? 1 : 0

  name        = "${local.name_prefix}/llm-api-key"
  description = "LLM API key"
  kms_key_id  = var.kms_key_arn != "" ? var.kms_key_arn : null

  tags = local.common_tags
}

# =============================================================================
# CloudWatch
# =============================================================================

resource "aws_cloudwatch_log_group" "connector" {
  count = var.enable_cloudwatch ? 1 : 0

  name              = "/connector/${var.environment}"
  retention_in_days = var.log_retention_days
  kms_key_id        = var.kms_key_arn != "" ? var.kms_key_arn : null

  tags = local.common_tags
}

# =============================================================================
# IAM
# =============================================================================

resource "aws_iam_role" "connector" {
  name = "${local.name_prefix}-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = "sts:AssumeRoleWithWebIdentity"
        Effect = "Allow"
        Principal = {
          Federated = module.eks.oidc_provider_arn
        }
        Condition = {
          StringEquals = {
            "${module.eks.oidc_provider}:sub" = "system:serviceaccount:connector:connector"
          }
        }
      }
    ]
  })

  tags = local.common_tags
}

resource "aws_iam_role_policy" "connector_secrets" {
  count = var.enable_secrets_manager ? 1 : 0

  name = "${local.name_prefix}-secrets-policy"
  role = aws_iam_role.connector.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = [
          "secretsmanager:GetSecretValue",
          "secretsmanager:DescribeSecret"
        ]
        Resource = [
          aws_secretsmanager_secret.connector[0].arn,
          aws_secretsmanager_secret.llm_api_key[0].arn
        ]
      }
    ]
  })
}

resource "aws_iam_role_policy" "connector_kms" {
  count = var.kms_key_arn != "" ? 1 : 0

  name = "${local.name_prefix}-kms-policy"
  role = aws_iam_role.connector.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = [
          "kms:Decrypt",
          "kms:Encrypt",
          "kms:GenerateDataKey"
        ]
        Resource = var.kms_key_arn
      }
    ]
  })
}

# =============================================================================
# Kubernetes Resources
# =============================================================================

resource "kubernetes_namespace" "connector" {
  metadata {
    name = "connector"
    labels = {
      name = "connector"
    }
  }

  depends_on = [module.eks]
}

resource "kubernetes_service_account" "connector" {
  metadata {
    name      = "connector"
    namespace = kubernetes_namespace.connector.metadata[0].name
    annotations = {
      "eks.amazonaws.com/role-arn" = aws_iam_role.connector.arn
    }
  }
}

resource "kubernetes_storage_class" "efs" {
  metadata {
    name = "connector-efs"
  }

  storage_provisioner = "efs.csi.aws.com"
  reclaim_policy      = "Retain"

  parameters = {
    provisioningMode = "efs-ap"
    fileSystemId     = aws_efs_file_system.connector.id
    directoryPerms   = "700"
  }
}

# =============================================================================
# Outputs
# =============================================================================

output "cluster_name" {
  description = "EKS cluster name"
  value       = module.eks.cluster_name
}

output "cluster_endpoint" {
  description = "EKS cluster endpoint"
  value       = module.eks.cluster_endpoint
}

output "cluster_security_group_id" {
  description = "Security group ID for the cluster"
  value       = module.eks.cluster_security_group_id
}

output "efs_id" {
  description = "EFS file system ID"
  value       = aws_efs_file_system.connector.id
}

output "connector_role_arn" {
  description = "IAM role ARN for Connector pods"
  value       = aws_iam_role.connector.arn
}

output "secrets_manager_arns" {
  description = "Secrets Manager secret ARNs"
  value = var.enable_secrets_manager ? {
    config      = aws_secretsmanager_secret.connector[0].arn
    llm_api_key = aws_secretsmanager_secret.llm_api_key[0].arn
  } : {}
}

output "kubeconfig_command" {
  description = "Command to update kubeconfig"
  value       = "aws eks update-kubeconfig --region ${var.region} --name ${module.eks.cluster_name}"
}
