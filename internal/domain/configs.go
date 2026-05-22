package domain

type VPNConfig struct {
	Type string `json:"type"` // vless или vmess
	Name string `json:"name"` // Имя сервера (отображается в списке)
	Addr string `json:"addr"` // IP или домен
	Port int    `json:"port"`
	UUID string `json:"uuid"`
}

type VMessJSON struct {
	Add  string `json:"add"`  // Хост / IP
	Port any    `json:"port"` // Может прийти как строка "443" или как число 443
	ID   string `json:"id"`   // UUID
	Ps   string `json:"ps"`   // Название (Имя сервера)
	Net  string `json:"net"`  // Тип транспорта (tcp, ws, grpc)
	Type string `json:"type"` // Тип обфускации
}
