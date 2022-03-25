# The Tagging Controller

The tagging controller is responsible for tagging and untagging node resources when they join and leave the cluster, respectively. It can add and remove tags based on user input. Unlike the existing controllers, the tagging controller works exclusively with AWS. The AWS APIs it uses are `ec2:CreateTags` and `ec2:DeleteTags`.

| Flag | Valid Values | Default | Description |
|------| --- | --- | --- |
| tags          | Comma-separated list of key=value | -   | A comma-separated list of key-value pairs which will be recorded as nodes' additional tags. For example: "Key1=Val1,Key2=Val2,KeyNoVal1=,KeyNoVal2" |