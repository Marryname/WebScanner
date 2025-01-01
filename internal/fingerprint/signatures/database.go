package fingerprint

import (
	"encoding/json"
	"os"
	"sync"
)

// SignatureDB 指纹数据库
type SignatureDB struct {
	sync.RWMutex
	signatures map[string][]Signature
	dbPath     string
}

// Signature 服务指纹结构
type Signature struct {
	Pattern     string   `json:"pattern"`
	ServiceName string   `json:"service_name"`
	Versions    []string `json:"versions,omitempty"`
	Products    []string `json:"products,omitempty"`
	CPE         string   `json:"cpe,omitempty"`
}

// NewSignatureDB 创建新的指纹数据库
func NewSignatureDB(dbPath string) (*SignatureDB, error) {
	db := &SignatureDB{
		signatures: make(map[string][]Signature),
		dbPath:     dbPath,
	}

	if err := db.load(); err != nil {
		return nil, err
	}

	return db, nil
}

// load 加载指纹数据库
func (db *SignatureDB) load() error {
	db.Lock()
	defer db.Unlock()

	// 读取指纹数据库文件
	data, err := os.ReadFile(db.dbPath)
	if err != nil {
		return err
	}

	return json.Unmarshal(data, &db.signatures)
}

// Save 保存指纹数据库
func (db *SignatureDB) Save() error {
	db.RLock()
	defer db.RUnlock()

	data, err := json.MarshalIndent(db.signatures, "", "  ")
	if err != nil {
		return err
	}

	return os.WriteFile(db.dbPath, data, 0644)
}

// AddSignature 添加新的指纹
func (db *SignatureDB) AddSignature(service string, sig Signature) {
	db.Lock()
	defer db.Unlock()

	db.signatures[service] = append(db.signatures[service], sig)
}

// GetSignatures 获取指定服务的所有指纹
func (db *SignatureDB) GetSignatures(service string) []Signature {
	db.RLock()
	defer db.RUnlock()

	return db.signatures[service]
}
