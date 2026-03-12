# HYDRA Terraform Infrastructure

Modular Terraform configuration for deploying HYDRA's cloud infrastructure on AWS.

## Modules

| Module | Description | Key Resources |
|--------|-------------|---------------|
| `vpc` | Network infrastructure | VPC, subnets, NAT gateway, security groups |
| `rds` | PostgreSQL database | RDS PostgreSQL 16 with pgvector, read replicas |
| `eks` | Kubernetes cluster | EKS with managed node groups |
| `redis` | Cache layer | ElastiCache Redis 7 |

## Environments

| Environment | Instance Sizes | Multi-AZ | Read Replicas |
|-------------|---------------|----------|---------------|
| `dev` | t3.micro/medium | No | 0 |
| `prod` | r6g.large/m6i.xlarge | Yes | 2 |

## Quick Start

### Prerequisites

- Terraform >= 1.5.0
- AWS CLI configured with appropriate credentials
- S3 bucket + DynamoDB table for remote state (production)

### Deploy Development Environment

```bash
cd terraform/environments/dev

# Initialize
terraform init

# Plan
terraform plan -var="db_password=your-secure-password"

# Apply
terraform apply -var="db_password=your-secure-password"
```

### Deploy Production Environment

```bash
cd terraform/environments/prod

# Initialize (uncomment backend config in main.tf first)
terraform init

# Plan with production variables
terraform plan -var="db_password=$DB_PASSWORD"

# Apply
terraform apply -var="db_password=$DB_PASSWORD"
```

### Connect to EKS

```bash
aws eks update-kubeconfig --name hydra-dev --region us-east-1
kubectl get nodes
```

### Deploy HYDRA to EKS

After infrastructure is provisioned:

```bash
# Option A: Kustomize
kubectl apply -k k8s/overlays/production/

# Option B: Helm
helm install hydra ./helm/hydra \
  --set secrets.databaseUrl="$(terraform output -raw database_url)" \
  --set worker.env.REDIS_URL="$(terraform output -raw redis_url)"
```

## Module Usage

### VPC Module

```hcl
module "vpc" {
  source = "../../modules/vpc"

  project              = "hydra"
  environment          = "dev"
  vpc_cidr             = "10.0.0.0/16"
  availability_zones   = ["us-east-1a", "us-east-1b"]
  private_subnet_cidrs = ["10.0.1.0/24", "10.0.2.0/24"]
  public_subnet_cidrs  = ["10.0.101.0/24", "10.0.102.0/24"]
}
```

### RDS Module

```hcl
module "rds" {
  source = "../../modules/rds"

  project            = "hydra"
  environment        = "prod"
  vpc_id             = module.vpc.vpc_id
  subnet_ids         = module.vpc.private_subnet_ids
  security_group_ids = [module.vpc.database_security_group_id]
  db_password        = var.db_password
  multi_az           = true
  read_replica_count = 2
}
```

## State Management

For production, enable remote state by uncommenting the backend block:

```hcl
backend "s3" {
  bucket         = "hydra-terraform-state"
  key            = "prod/terraform.tfstate"
  region         = "us-east-1"
  dynamodb_table = "hydra-terraform-locks"
  encrypt        = true
}
```

Create the S3 bucket and DynamoDB table first:

```bash
aws s3api create-bucket --bucket hydra-terraform-state --region us-east-1
aws dynamodb create-table \
  --table-name hydra-terraform-locks \
  --attribute-definitions AttributeName=LockID,AttributeType=S \
  --key-schema AttributeName=LockID,KeyType=HASH \
  --billing-mode PAY_PER_REQUEST
```
