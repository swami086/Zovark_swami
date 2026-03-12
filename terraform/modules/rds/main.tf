# ============================================================
# HYDRA RDS Module — PostgreSQL with pgvector
# Creates RDS PostgreSQL instance with read replicas
# ============================================================

variable "project" {
  description = "Project name"
  type        = string
  default     = "hydra"
}

variable "environment" {
  description = "Environment (dev, staging, prod)"
  type        = string
}

variable "vpc_id" {
  description = "VPC ID"
  type        = string
}

variable "subnet_ids" {
  description = "Subnet IDs for DB subnet group"
  type        = list(string)
}

variable "security_group_ids" {
  description = "Security group IDs"
  type        = list(string)
}

variable "instance_class" {
  description = "RDS instance class"
  type        = string
  default     = "db.t3.medium"
}

variable "allocated_storage" {
  description = "Storage in GB"
  type        = number
  default     = 50
}

variable "max_allocated_storage" {
  description = "Maximum autoscaled storage in GB"
  type        = number
  default     = 200
}

variable "db_name" {
  description = "Database name"
  type        = string
  default     = "hydra"
}

variable "db_username" {
  description = "Master username"
  type        = string
  default     = "hydra"
}

variable "db_password" {
  description = "Master password"
  type        = string
  sensitive   = true
}

variable "multi_az" {
  description = "Enable Multi-AZ deployment"
  type        = bool
  default     = false
}

variable "read_replica_count" {
  description = "Number of read replicas"
  type        = number
  default     = 0
}

variable "backup_retention_period" {
  description = "Backup retention in days"
  type        = number
  default     = 7
}

variable "tags" {
  description = "Additional tags"
  type        = map(string)
  default     = {}
}

# ─── DB SUBNET GROUP ────────────────────────────────────

resource "aws_db_subnet_group" "main" {
  name       = "${var.project}-${var.environment}-db-subnet"
  subnet_ids = var.subnet_ids

  tags = merge(var.tags, {
    Name = "${var.project}-${var.environment}-db-subnet"
  })
}

# ─── PARAMETER GROUP ────────────────────────────────────

resource "aws_db_parameter_group" "main" {
  name   = "${var.project}-${var.environment}-pg16"
  family = "postgres16"

  parameter {
    name  = "shared_preload_libraries"
    value = "pg_stat_statements,vector"
  }

  parameter {
    name  = "log_min_duration_statement"
    value = "1000"
  }

  parameter {
    name  = "max_connections"
    value = "200"
  }

  parameter {
    name         = "work_mem"
    value        = "16384"
    apply_method = "pending-reboot"
  }

  tags = merge(var.tags, {
    Name = "${var.project}-${var.environment}-pg-params"
  })
}

# ─── RDS INSTANCE (PRIMARY) ─────────────────────────────

resource "aws_db_instance" "primary" {
  identifier     = "${var.project}-${var.environment}-postgres"
  engine         = "postgres"
  engine_version = "16.4"
  instance_class = var.instance_class

  allocated_storage     = var.allocated_storage
  max_allocated_storage = var.max_allocated_storage
  storage_type          = "gp3"
  storage_encrypted     = true

  db_name  = var.db_name
  username = var.db_username
  password = var.db_password

  db_subnet_group_name   = aws_db_subnet_group.main.name
  vpc_security_group_ids = var.security_group_ids
  parameter_group_name   = aws_db_parameter_group.main.name

  multi_az            = var.multi_az
  publicly_accessible = false

  backup_retention_period = var.backup_retention_period
  backup_window           = "03:00-04:00"
  maintenance_window      = "sun:04:00-sun:05:00"

  deletion_protection       = var.environment == "prod"
  skip_final_snapshot       = var.environment != "prod"
  final_snapshot_identifier = var.environment == "prod" ? "${var.project}-${var.environment}-final" : null

  performance_insights_enabled = true

  tags = merge(var.tags, {
    Name        = "${var.project}-${var.environment}-postgres"
    Component   = "database"
    Environment = var.environment
  })
}

# ─── READ REPLICAS ──────────────────────────────────────

resource "aws_db_instance" "replica" {
  count = var.read_replica_count

  identifier          = "${var.project}-${var.environment}-postgres-replica-${count.index + 1}"
  replicate_source_db = aws_db_instance.primary.identifier
  instance_class      = var.instance_class

  storage_encrypted  = true
  publicly_accessible = false

  vpc_security_group_ids = var.security_group_ids
  parameter_group_name   = aws_db_parameter_group.main.name

  performance_insights_enabled = true

  tags = merge(var.tags, {
    Name        = "${var.project}-${var.environment}-postgres-replica-${count.index + 1}"
    Component   = "database-replica"
    Environment = var.environment
  })
}

# ─── OUTPUTS ─────────────────────────────────────────────

output "primary_endpoint" {
  value = aws_db_instance.primary.endpoint
}

output "primary_address" {
  value = aws_db_instance.primary.address
}

output "replica_endpoints" {
  value = aws_db_instance.replica[*].endpoint
}

output "database_url" {
  value     = "postgresql://${var.db_username}:${var.db_password}@${aws_db_instance.primary.endpoint}/${var.db_name}"
  sensitive = true
}
