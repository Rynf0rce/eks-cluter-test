variable "project_name" {
  description = "Project name that the EKS cluster will use"
  type        = string
  default     = "jinwoo-eks-cluster"
}

variable "eks_cluster_version" {
  description = "Kubernetes `<major>.<minor>` version to use for the EKS cluster (i.e.: `1.27`)"
  type        = string
  default     = "1.32"
}

variable "node_group_name" {
  description = "Kubernetes node group name"
  type        = string
  default     = "managed-ondemand"
}

variable "vpc_cidr" {
  description = "CIDR for the VPC that the EKS cluster will use"
  type        = string
  default     = "10.39.0.0/16"
}

variable "deploy_region" {
  description = "The AWS region to deploy into (e.g. us-east-1)"
  type        = string
  default     = "ap-northeast-3"
}

variable "aws_alb_controller_name" {
  description = "AWS ALB controller name"
  type        = string
  default     = "aws-load-balancer-controller"
}

variable "aws_load_balancer_controller_image_tag" {
  description = "Desired AWS ALB Controller image tag to pull"
  type        = string
  default     = "v2.8.2"
}

variable "eks_managed_nodes_instance_types" {
  description = "Desired instance type(s) to use as worker node(s)"
  type        = list(string)
  default     = ["t3.medium"]
}

variable "eks_managed_nodes_capacity_type" {
  description = "Desired AWS ALB Controller image tag to pull"
  type        = string
  default     = "SPOT"
  validation {
    condition     = contains(["SPOT", "ON_DEMAND"], var.eks_managed_nodes_capacity_type)
    error_message = "Valid values for eks_managed_nodes_capacity_type are (SPOT, ON_DEMAND)"
  }
}

variable "kube_prometheus_stack_chart_version" {
  description = "Desired Kube Prometheus Stack Help chart version"
  type        = string
  default     = "69.5.2"
}

variable "karpenter_chart_version" {
  description = "Desired Karpenter Help chart version"
  type        = string
  default     = "1.0.1"
}

variable "karpenter_arch_choices" {
  description = "Allowed Karpenter node architecture choices"
  type        = list(string)
  default     = ["amd64"]
}

variable "karpenter_instance_cpu_choices" {
  description = "Allowed Karpenter instance cpu choices"
  type        = list(string)
  default     = ["2", "4"]
  # default     = ["2", "4", "8", "16", "32", "48", "64"]
}

variable "karpenter_capacity_type_choices" {
  description = "Allowed Karpenter instance category choices"
  type        = list(string)
  default     = ["spot", "on-demand"]
}

variable "karpenter_instance_category_choices" {
  description = "Allowed Karpenter instance categories"
  type        = list(string)
  default     = ["c", "t"]
  # default     = ["c", "t", "m", "r", "i", "d"]
}

variable "external_secrets_service_account_name" {
  description = "external secrets addon service account name"
  type        = string
  default     = "jinwoo-external-secrets-sa"
}

variable "external_secrets_helm_chart_version" {
  description = "external secrets helm chart version"
  type        = string
  default     = "0.10.3"
}