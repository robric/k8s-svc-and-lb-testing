#!/bin/bash

# Find the first pod running on vm1
POD_NAME=$(kubectl get pods -o wide | grep vm1 | awk '{print $1}' | head -n 1)

# Check if a pod was found
if [ -n "$POD_NAME" ]; then
  echo "Executing bash in pod: $POD_NAME"
  kubectl exec -it "$POD_NAME" -- bash
else
  echo "No pod found on vm1."
fi