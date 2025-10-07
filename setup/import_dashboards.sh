#!/bin/sh
set -e

ES="http://elasticsearch:9200"
KB="http://kibana:5601"
KBN_USER=""  # not used (xpack.security disabled)
KBN_PASSWORD=""
RETRY=60

echo "Waiting for Elasticsearch..."
i=0
while [ $i -lt $RETRY ]; do
  if curl -s ${ES} >/dev/null; then
    echo "Elasticsearch is up"
    break
  fi
  i=$((i+1))
  sleep 2
done

echo "Waiting for Kibana..."
i=0
while [ $i -lt $RETRY ]; do
  if curl -s ${KB} >/dev/null; then
    echo "Kibana is up"
    break
  fi
  i=$((i+1))
  sleep 2
done

# Create an index template (optional) for mordor indices
curl -s -X PUT "${ES}/_index_template/mordor_template" -H 'Content-Type: application/json' -d '{
  "index_patterns": ["mordor-*"],
  "template": {
    "mappings": {
      "properties": {
        "@timestamp": { "type": "date" },
        "src": {
          "properties": {
            "ip": { "type": "ip" }
          }
        },
        "dest": {
          "properties": {
            "ip": { "type": "ip" }
          }
        }
      }
    }
  }
}'

# Import Kibana saved objects (simple import)
if [ -f /kibana/dashboards/mordor_dashboard.ndjson ]; then
  echo "Importing Kibana saved objects..."
  curl -s -X POST "${KB}/api/saved_objects/_import?overwrite=true" \
    -H "kbn-xsrf: true" \
    --form file=@/kibana/dashboards/mordor_dashboard.ndjson
  echo "Kibana objects import response: done"
else
  echo "No dashboard NDJSON found at /kibana/dashboards/mordor_dashboard.ndjson - skipping Kibana import"
fi

# Optionally trigger a Logstash once to pick up files (if logstash file input is running we don't need to)
echo "Setup finished."
# keep container alive briefly so logs are visible
sleep 5
