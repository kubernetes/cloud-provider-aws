# Existing-cluster examples

The base example enables `--use-service-account-credentials=true`. Its
`controller-credentials` Role permits service-account lookup and token creation
for the controller manager's five account names in `kube-system`:
`node-controller`, `service-controller`, `route-controller`,
`aws-cloud-provider`, and `tagging-controller`.

The `superset-role` overlay uses the controller manager's own credentials for all
controllers. It empties the controller credential Role because separate tokens
are unnecessary in this mode. Keeping the empty Role allows an application of
the overlay to replace an existing base Role without requiring resource pruning.

Apply the complete base or overlay, including its RBAC resources, when updating
an existing installation:

```console
kubectl apply -k examples/existing-cluster/base
# Or, for shared controller credentials:
kubectl apply -k examples/existing-cluster/overlays/superset-role
```

The credential builder uses `kube-system` for controller accounts independently
of the controller manager workload's namespace. If adapting these examples to
run the workload elsewhere, keep the credential Role and RoleBinding in
`kube-system` and update the binding's service-account subject accordingly.
