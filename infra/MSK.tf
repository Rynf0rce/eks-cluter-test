resource "aws_security_group" "msk_sg" {
  name        = "${var.project_name}-msk-sg"
  description = "Security group for MSK cluster"
  vpc_id      = module.vpc.vpc_id

  ingress {
    from_port   = 9092
    to_port     = 9092
    protocol    = "tcp"
    cidr_blocks = [var.vpc_cidr]
    description = "Allow Kafka plaintext protocol within VPC"
  }

  ingress {
    from_port   = 9094
    to_port     = 9094
    protocol    = "tcp"
    cidr_blocks = [var.vpc_cidr]
    description = "Allow Kafka TLS protocol within VPC"
  }

  ingress {
    from_port   = 2181
    to_port     = 2181
    protocol    = "tcp"
    cidr_blocks = [var.vpc_cidr]
    description = "Allow ZooKeeper protocol within VPC"
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
    description = "Allow all outbound traffic"
  }

  tags = local.tags
}

resource "aws_cloudwatch_log_group" "msk_log_group" {
  name              = "/aws/msk/${var.project_name}-kafka"
  retention_in_days = 7
  tags              = local.tags
}

resource "aws_msk_configuration" "shopping_kafka_config" {
  name = "${var.project_name}-kafka-config"

  server_properties = <<PROPERTIES
auto.create.topics.enable=true
delete.topic.enable=true
default.replication.factor=3
min.insync.replicas=2
num.partitions=3
num.io.threads=8
num.network.threads=5
PROPERTIES

  kafka_versions = ["3.5.1"]
}

resource "aws_msk_cluster" "shopping_kafka_cluster" {
  cluster_name           = "${var.project_name}-kafka"
  kafka_version          = "3.5.1"
  number_of_broker_nodes = 3

  broker_node_group_info {
    instance_type   = "kafka.t3.small"
    client_subnets  = module.vpc.private_subnets
    security_groups = [aws_security_group.msk_sg.id]
    storage_info {
      ebs_storage_info {
        volume_size = 100
      }
    }
  }

  configuration_info {
    arn      = aws_msk_configuration.shopping_kafka_config.arn
    revision = aws_msk_configuration.shopping_kafka_config.latest_revision
  }

  encryption_info {
    encryption_in_transit {
      client_broker = "TLS_PLAINTEXT"
      in_cluster    = true
    }
  }

  open_monitoring {
    prometheus {
      jmx_exporter {
        enabled_in_broker = true
      }
      node_exporter {
        enabled_in_broker = true
      }
    }
  }

  logging_info {
    broker_logs {
      cloudwatch_logs {
        enabled   = true
        log_group = aws_cloudwatch_log_group.msk_log_group.name
      }
    }
  }

  tags = local.tags

  depends_on = [
    module.vpc
  ]
}

# IAM Role for EKS nodes to access MSK
resource "aws_iam_policy" "eks_msk_access" {
  name        = "${var.project_name}-eks-msk-access"
  description = "Policy for EKS nodes to access MSK cluster"

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = [
          "kafka:DescribeCluster",
          "kafka:GetBootstrapBrokers",
          "kafka:ListScramSecrets",
          "kafka:DescribeClusterV2",
          "kafka:DescribeClusterOperation",
          "kafka:DescribeConfiguration"
        ]
        Effect   = "Allow"
        Resource = aws_msk_cluster.shopping_kafka_cluster.arn
      },
    ]
  })
}

# Get the node IAM role name from the EKS cluster
data "aws_eks_cluster" "this" {
  name = module.eks.cluster_name
}

data "aws_eks_node_groups" "all" {
  cluster_name = data.aws_eks_cluster.this.name
}

data "aws_eks_node_group" "node_group" {
  for_each = toset(data.aws_eks_node_groups.all.names)

  cluster_name    = data.aws_eks_cluster.this.name
  node_group_name = each.value
}

locals {
  node_role_names = distinct([
    for ng_name, ng in data.aws_eks_node_group.node_group : ng.node_role_arn
  ])
}

resource "aws_iam_role_policy_attachment" "eks_msk_access_attachment" {
  count = length(local.node_role_names)

  # Extract the role name from the ARN
  role       = element(split("/", local.node_role_names[count.index]), 1)
  policy_arn = aws_iam_policy.eks_msk_access.arn
}

resource "kubernetes_namespace" "shopping_app" {
  metadata {
    name = "shopping-app"
    labels = {
      name        = "shopping-app"
      app         = "shopping-app"
      monitoring  = "true"
    }
  }
}

# Export the MSK bootstrap brokers to a ConfigMap for application use
resource "kubernetes_config_map" "msk_config" {
  metadata {
    name      = "msk-config"
    namespace = kubernetes_namespace.shopping_app.metadata[0].name
  }

  data = {
    "kafka.bootstrap.servers" = aws_msk_cluster.shopping_kafka_cluster.bootstrap_brokers
  }

  depends_on = [
    aws_msk_cluster.shopping_kafka_cluster,
    kubernetes_namespace.shopping_app
  ]
}

output "msk_bootstrap_brokers_plaintext" {
  description = "MSK Cluster bootstrap brokers for plaintext connections"
  value       = aws_msk_cluster.shopping_kafka_cluster.bootstrap_brokers
}

output "msk_bootstrap_brokers_tls" {
  description = "MSK Cluster bootstrap brokers for TLS connections"
  value       = aws_msk_cluster.shopping_kafka_cluster.bootstrap_brokers_tls
}