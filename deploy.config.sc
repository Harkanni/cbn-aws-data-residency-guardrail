cp terraform.tfvars.example terraform.tfvars   # set alert_email
chmod +x deploy.sh
./deploy.sh install-tf && export PATH="$HOME/bin:$PATH"   # only if terraform is missing
./deploy.sh bootstrap    # asks AWS to enable af-south-1; wait a few minutes
./deploy.sh check        # root-user check, region status, existing Config recorder
./deploy.sh up           # init, plan, then asks "yes" before applying