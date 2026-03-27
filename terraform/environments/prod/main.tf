# ============================================================
# ZOVARC Production Environment — Terraform Configuration
# High availability, multi-AZ, encrypted, production-hardened
# ============================================================

terraform {
  required_version = ">= 1.5.0"

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
  }

  # Remote state (required for production)
  # backend "s3" {
  #   bucket         = "zovarc-terraform-state"
  #   key            = "prod/terraform.tfstate"
  #   region         = "us-east-1"
  #   dynamodb_table = "zovarc-terraform-locks"
  #   encrypt        = true
  # }
}

provider "aws" {
  region = var.aws_region

  default_tags {
    tags = {
      Project     = "zovarc"
      Environment = "prod"
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
}

# ─── VPC ─────────────────────────────────────────────────

module "vpc" {
  source = "../../modules/vpc"

  project     = "zovarc"
  environment = "prod"
  vpc_cidr    = "10.0.0.0/16"

  availability_zones   = ["${var.aws_region}a", "${var.aws_region}b", "${var.aws_region}c"]
  private_subnet_cidrs = ["10.0.1.0/24", "10.0.2.0/24", "10.0.3.0/24"]
  public_subnet_cidrs  = ["10.0.101.0/24", "10.0.102.0/24", "10.0.103.0/24"]
}

# ─── RDS (PostgreSQL) ───────────────────────────────────

module "rds" {
  source = "../../modules/rds"

  project     = "zovarc"
  environment = "prod"
  vpc_id      = module.vpc.vpc_id
  subnet_ids  = module.vpc.private_subnet_ids

  security_group_ids = [module.vpc.database_security_group_id]

  instance_class        = "db.r6g.large"
  allocated_storage     = 100
  max_allocated_storage = 500
  db_password           = var.db_password
  multi_az              = true
  read_replica_count    = 2
  backup_retention_period = 30
}

# ─── Redis (ElastiCache) ────────────────────────────────

module "redis" {
  source = "../../modules/redis"

  project     = "zovarc"
  environment = "prod"
  vpc_id      = module.vpc.vpc_id
  subnet_ids  = module.vpc.private_subnet_ids

  security_group_ids = [module.vpc.redis_security_group_id]

  node_type       = "cache.r6g.large"
  num_cache_nodes = 1
  engine_version  = "7.0"
}

# ─── EKS ─────────────────────────────────────────────────

module "eks" {
  source = "../../modules/eks"

  project     = "zovarc"
  environment = "prod"
  vpc_id      = module.vpc.vpc_id
  subnet_ids  = module.vpc.private_subnet_ids

  kubernetes_version  = "1.29"
  node_instance_types = ["m6i.xlarge"]
  node_min_size       = 3
  node_max_size       = 20
  node_desired_size   = 5
}

# ─── OUTPUTS ─────────────────────────────────────────────

output "vpc_id" {
  value = module.vpc.vpc_id
}

output "eks_cluster_name" {
  value = module.eks.cluster_name
}

output "eks_cluster_endpoint" {
  value     = module.eks.cluster_endpoint
  sensitive = true
}

output "rds_primary_endpoint" {
  value = module.rds.primary_endpoint
}

output "rds_replica_endpoints" {
  value = module.rds.replica_endpoints
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
