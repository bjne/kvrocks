#include "table_properties_collector.h"
#include <utility>
#include "encoding.h"
#include "redis_metadata.h"
#include "server.h"

rocksdb::Status
CompactOnExpiredCollector::AddUserKey(const rocksdb::Slice &key, const rocksdb::Slice &value,
    rocksdb::EntryType entry_type, rocksdb::SequenceNumber, uint64_t) {
  int now;
  uint8_t type;
  uint32_t expired, subkeys = 0;
  uint64_t version;

  if (start_key_.empty()) {
    start_key_ = key.ToString();
  }
  stop_key_ = key.ToString();
  total_keys_ += 1;
  if (entry_type == rocksdb::kEntryDelete) {
    deleted_keys_ += 1;
    return rocksdb::Status::OK();
  }

  if (cf_name_ != "metadata") {
    return rocksdb::Status::OK();
  }
  rocksdb::Slice cv = value;
  if (entry_type != rocksdb::kEntryPut || cv.size() < 5) {
    return rocksdb::Status::OK();
  }
  GetFixed8(&cv, &type);
  GetFixed32(&cv, &expired);
  type = type & (uint8_t)0x0f;
  if (type == kRedisSet || type == kRedisList) {
      if (cv.size() <= 12) return rocksdb::Status::OK();
      GetFixed64(&cv, &version);
      GetFixed32(&cv, &subkeys);
  }
  total_keys_ += subkeys;
  now = Server::GetUnixTime();
  if ((expired > 0 && expired < static_cast<uint32_t>(now))
      || (type != kRedisString && subkeys == 0)) {
    deleted_keys_ += subkeys + 1;
  }
  return rocksdb::Status::OK();
}

rocksdb::Status
CompactOnExpiredCollector::Finish(rocksdb::UserCollectedProperties *properties) {
  properties->insert(std::pair<std::string, std::string>{"total_keys", std::to_string(total_keys_)});
  properties->insert(std::pair<std::string, std::string>{"deleted_keys", std::to_string(deleted_keys_)});
  properties->insert(std::pair<std::string, std::string>{"start_key", start_key_});
  properties->insert(std::pair<std::string, std::string>{"stop_key", stop_key_});
  return rocksdb::Status::OK();
}

rocksdb::UserCollectedProperties
CompactOnExpiredCollector::GetReadableProperties() const {
  rocksdb::UserCollectedProperties properties;
  properties.insert(std::pair<std::string, std::string>{"total_keys", std::to_string(total_keys_)});
  properties.insert(std::pair<std::string, std::string>{"deleted_keys", std::to_string(deleted_keys_)});
  return properties;
}

bool CompactOnExpiredCollector::NeedCompact() const {
  if (total_keys_ == 0) return false;
  return static_cast<float>(deleted_keys_)/ static_cast<float>(total_keys_) > trigger_threshold_;
}

rocksdb::TablePropertiesCollector *
CompactOnExpiredTableCollectorFactory::CreateTablePropertiesCollector(
    rocksdb::TablePropertiesCollectorFactory::Context context) {
  return new CompactOnExpiredCollector(cf_name_, trigger_threshold_);
}
std::shared_ptr<CompactOnExpiredTableCollectorFactory>
NewCompactOnExpiredTableCollectorFactory(const std::string &cf_name,
                                         float trigger_threshold) {
  return std::shared_ptr<CompactOnExpiredTableCollectorFactory>(
      new CompactOnExpiredTableCollectorFactory(cf_name, trigger_threshold));
}
