# The Tagging Controller

The tagging controller is responsible for tagging and untagging node resources when it joins and leaves the cluster respectively. It can add and remove tags based on user input. Unlike the existing controllers, the tagging controller is working exclusively with AWS as we want to tag the resources (EC instances for example). For functionalities used by the controller, we primarily use `CreateTags` and `DeleteTags` from `EC2`.

| Flag | Valid Values | Default | Description |
|------| --- | --- | --- |
| tags          | Comma-separated list of key=value | -   | A comma-separated list of key-value pairs which will be recorded as nodes' additional tags. For example: "Key1=Val1,Key2=Val2,KeyNoVal1=,KeyNoVal2" |