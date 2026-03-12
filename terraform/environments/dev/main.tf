# ============================================================
# HYDRA Development Environment — Terraform Configuration
# Cost-optimized for development and testing
# ============================================================

terraform {
  required_version = ">= 1.5.0"

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
  }

  # Uncomment for remote state
  # backend "s3" {
  #   bucket         = "hydra-terraform-state"
  #   key            = "dev/terraform.tfstate"
  #   region         = "us-east-1"
  #   dynamodb_table = "hydra-terraform-locks"
  #   encrypt        = true
  # }
}

provider "aws" {
  region = var.aws_region

  default_tags {
    tags = {
      Project     = "hydra"
      Environment = "dev"
      ManagedBy   = "terraform"
    }
  }
}

variable "aws_region" {
  description = "AWS region"
  type        = string
  default     = "us-east-1"
}

variable "db_password" {
  description = "Database password"
  type        = string
  sensitive   = true
  default     = "hydra_dev_2026"
}

# ─── VPC ─────────────────────────────────────────────────

module "vpc" {
  source = "../../modules/vpc"

  project     = "hydra"
  environment = "dev"
  vpc_cidr    = "10.0.0.0/16"

  availability_zones   = ["${var.aws_region}a", "${var.aws_region}b"]
  private_subnet_cidrs = ["10.0.1.0/24", "10.0.2.0/24"]
  public_subnet_cidrs  = ["10.0.101.0/24", "10.0.102.0/24"]
}

# ─── RDS (PostgreSQL) ───────────────────────────────────

module "rds" {
  source = "../../modules/rds"

  project     = "hydra"
  environment = "dev"
  vpc_id      = module.vpc.vpc_id
  subnet_ids  = module.vpc.private_subnet_ids

  security_group_ids = [module.vpc.database_security_group_id]

  instance_class        = "db.t3.micro"
  allocated_storage     = 20
  max_allocated_storage = 50
  db_password           = var.db_password
  multi_az              = false
  read_replica_count    = 0
  backup_retention_period = 3
}

# ─── Redis (ElastiCache) ────────────────────────────────

module "redis" {
  source = "../../modules/redis"

  project     = "hydra"
  environment = "dev"
  vpc_id      = module.vpc.vpc_id
  subnet_ids  = module.vpc.private_subnet_ids

  security_group_ids = [module.vpc.redis_security_group_id]

  node_type       = "cache.t3.micro"
  num_cache_nodes = 1
}

# ─── EKS ─────────────────────────────────────────────────

module "eks" {
  source = "../../modules/eks"

  project     = "hydra"
  environment = "dev"
  vpc_id      = module.vpc.vpc_id
  subnet_ids  = module.vpc.private_subnet_ids

  kubernetes_version  = "1.29"
  node_instance_types = ["t3.medium"]
  node_min_size       = 1
  node_max_size       = 4
  node_desired_size   = 2
}

# ─── OUTPUTS ─────────────────────────────────────────────

output "vpc_id" {
  value = module.vpc.vpc_id
}

output "eks_cluster_name" {
  value = module.eks.cluster_name
}

output "eks_cluster_endpoint" {
  value = module.eks.cluster_endpoint
}

output "rds_endpoint" {
  value = module.rds.primary_endpoint
}

output "redis_endpoint" {
  value = module.redis.redis_endpoint
}

output "database_url" {
  value     = module.rds.database_url
  sensitive = true
}

output "redis_url" {
  value = module.redis.redis_url
}
