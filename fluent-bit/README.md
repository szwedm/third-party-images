# Fluent Bit Docker Image

This image is based on the official [Fluent Bit Docker image](https://github.com/fluent/fluent-bit/blob/master/dockerfiles/Dockerfile).

The custom plugin has the following customizations:

* Loki output plugin
* Sequential HTTP output plugin

## Sequential HTTP output plugin

The standard HTTP output plugin `out-http` sends out records in batch. This is a problem for some consuming services in the SKR environment (e.g. SAP Audit Service).
The `out-sequentialhttp` is a drop-in replacement that sends out records sequentially (one-by-one).

### Code modifications

The code of `out-sequentialhttp` is almost identical to `out-http`. The only difference is how msgpack to JSON transcoding/sending to the HTTP backend is done in the `cb_http_flush` function.

> **NOTE:** Even though the `out-sequentialhttp` plugin sends out logs one-by-one, retry is still done for the whole batch. If one HTTP request fails, then all of the logs in the respective batch will be re-sent.

### Functional testing

To test the `out-sequentialhttp` plugin on an SKR cluster, deploy a mock HTTP server, and make the `sequentialhttp` plugin send the logs to the mock.

1. Deploy a mock server in the `kyma-system` Namespace:
```bash
kubectl create -f https://raw.githubusercontent.com/istio/istio/master/samples/httpbin/httpbin.yaml
```

2. Send dummy logs to the mock server. To do this, edit the `logging-fluent-bit-config` ConfigMap, and replace the following plugins in the `extra.conf` section:
* `http` output plugin → the `sequentialhttp` plugin
* `tail` input plugin → the `dummy plugin` to simulate sending audit log at a high rate (otherwise no batching would occur)

An example Fluent Bit configuration looks as follows:
```
      [INPUT]
              Name              dummy
              Tag               dex.log
              Rate              10
              Dummy             {"log":"{\"level\":\"info\",\"msg\":\"login successful: connector \"xsuaa\"\", \"username\":\"john.doe@sap.com\", \"preferred_username\":\"\", \"email\":\"john.doe@sap.com\", \"groups\":[\"tenantID=56b23cc1-d021-4344-9c24-bace8883b864\"],\"time\":\"2021-01-11T10:29:31Z\"}"}
      [OUTPUT]
              Name             sequentialhttp
              Match            dex.*
              Retry_Limit      False
              Host             httpbin
              Port             8000
              URI              /anything
              Header           Content-Type application/json
              Format           json_stream
              tls              off
```

3. Make Dex generate logs. For example, log into the Kyma Console multiple times. Then, check the logs of the `fluent-bit` Pod which runs on the same Node with Dex, and look for the log entries produced by `sequentialhttp`. Make sure that every requests delivers exactly one log entry.

```
kubectl logs {FLUENT_BIT_POD_COLOCATED_WITH_DEX} fluent-bit
```

4. Edit the `logging-fluent-bit-config` ConfigMap, and replace `sequentialhttp` with the old `http` plugin. Restart the Pod you observed in the previous step. Check the logs. Look for log entries produced by `http`. The requests now contain batched log entries.

### Load testing

To send dummy audit logs at high rate, edit the `logging-fluent-bit-config` ConfigMap, and replace the existing `tail` plugin with the following `dummy` plugin:
```
    [INPUT]
            Name              dummy
            Tag               dex.log
            Rate              10
            Dummy             {"log":"{\"level\":\"info\",\"msg\":\"login successful: connector \"xsuaa\"\", \"username\":\"john.doe@sap.com\", \"preferred_username\":\"\", \"email\":\"john.doe@sap.com\", \"groups\":[\"tenantID=56b23cc1-d021-4344-9c24-bace8883b864\"],\"time\":\"2021-01-11T10:29:31Z\"}"}
```
Observe memory usage of the Pod in Grafana, and make sure that memory consumption does not grow over time.
