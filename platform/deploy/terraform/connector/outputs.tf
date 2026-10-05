# Connector Terraform Outputs

output "cluster_name" {
  description = "EKS cluster name"
  value       = module.eks.cluster_name
}

output "cluster_endpoint" {
  description = "EKS cluster API endpoint"
  value       = module.eks.cluster_endpoint
}

output "cluster_certificate_authority" {
  description = "EKS cluster CA certificate"
  value       = module.eks.cluster_certificate_authority_data
  sensitive   = true
}

output "cluster_security_group_id" {
  description = "Security group ID attached to the EKS cluster"
  value       = module.eks.cluster_security_group_id
}

output "vpc_id" {
  description = "VPC ID"
  value       = module.vpc.vpc_id
}

output "private_subnet_ids" {
  description = "Private subnet IDs"
  value       = module.vpc.private_subnets
}

output "public_subnet_ids" {
  description = "Public subnet IDs"
  value       = module.vpc.public_subnets
}

output "efs_id" {
  description = "EFS file system ID for persistent storage"
  value       = aws_efs_file_system.connector.id
}

output "efs_dns_name" {
  description = "EFS DNS name"
  value       = aws_efs_file_system.connector.dns_name
}

output "connector_role_arn" {
  description = "IAM role ARN for Connector service account"
  value       = aws_iam_role.connector.arn
}

output "connector_namespace" {
  description = "Kubernetes namespace for Connector"
  value       = kubernetes_namespace.connector.metadata[0].name
}

output "secrets_manager_arns" {
  description = "AWS Secrets Manager secret ARNs"
  value = var.enable_secrets_manager ? {
    config      = aws_secretsmanager_secret.connector[0].arn
    llm_api_key = aws_secretsmanager_secret.llm_api_key[0].arn
  } : {}
}

output "cloudwatch_log_group" {
  description = "CloudWatch log group name"
  value       = var.enable_cloudwatch ? aws_cloudwatch_log_group.connector[0].name : null
}

output "kubeconfig_command" {
  description = "Command to configure kubectl"
  value       = "aws eks update-kubeconfig --region ${var.region} --name ${module.eks.cluster_name}"
}

output "helm_install_command" {
  description = "Command to install Connector via Helm"
  value       = <<-EOT
    helm install connector ./platform/deploy/helm/connector \
      --namespace ${kubernetes_namespace.connector.metadata[0].name} \
      --set image.tag=${var.connector_version} \
      --set resources.limits.cpu=${var.cpu_limit} \
      --set resources.limits.memory=${var.memory_limit} \
      --set serviceAccount.annotations."eks\.amazonaws\.com/role-arn"=${aws_iam_role.connector.arn}
  EOT
}
