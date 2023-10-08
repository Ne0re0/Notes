# AWS S3 Bucket (Simple Storage Service)
## Utility 
- Data storage
- Web app hosting
- File share
- ...

## Vocabulary
- Bucket = A top level Amazon folder
- Prefix = A folder in a bucker
- Object = Any item that's hosted in a bucket

Cli :
```bash
aws
```

## Cheat Sheet

```bash
aws configure # Note that fake values can be provided
```

```bash
aws s3 ls 
aws s3 ls s3://target.url
aws s3 <command> s3://target.url

aws s3 ls --endpoint-url=http://s3.example.url s3://thetoppers.htb # Note that in this case s3.example.url is a s3 service
aws s3 cp --endpoint-url=http://s3.example.url rev.php s3://thetoppers.htb

```

# Basic commands
```bash
aws s3 ls s3:// 
aws s3api list-buckets
aws s3 ls s3://bucket.com
aws s3 ls --recursive s3://bucket.com
aws s3 sync s3://bucketname s3-files-dir
aws s3 cp s3://bucket-name/<file> <destination>
aws s3 cp/mv test-file.txt s3://bucket-name
aws s3 rm s3://bucket-name/test-file.txt
aws s3api get-bucket-acl --bucket bucket-name # Check owner
aws s3api head-object --bucket bucket-name --key file.txt # Check file metadata
```