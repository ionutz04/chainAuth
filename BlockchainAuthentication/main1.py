import os
pub_key_path = os.path.expanduser(
            "~/Dropbox/facultate/an2/FILS/OS2/chainAuth/BlockchainAuthentication/keys/" 
            f"temperature_public.pem"
        )
with open(pub_key_path,"r")as f:
        print(f.read())