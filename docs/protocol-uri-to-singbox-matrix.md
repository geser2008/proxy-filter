# Матрица соответствия URI-протоколов и sing-box JSON

**Дата:** 2026-11-05. **Статус:** инженерная матрица, не доказательство полной совместимости.
**Цель:** определить целевой перевод URI → protocol-specific model → JSON outbound и различия с `type=parser` в `shtorm-7/sing-box-extended` tag `v1.14.3-extended-2.7.3`.

## Границы и обозначения

- Production ingest: **TXT / Base64(TXT) → URI**, схемы `vless`, `vmess`, `trojan`, `ss`, `hysteria2`/`hy2`, `tuic`. VMess payload — Base64(JSON); SS — SIP002 или legacy Base64.
- **URI** — входной синтаксис; **EXT** — поведение именно исходного link parser sing-box-extended на зафиксированном теге (а не generic/Xray спецификация); **JSON** — структурное поле outbound sing-box; **PF** — существующий mapper в `engine.py`/`singbox_backend.py` и отдельно эксперимент `native_experiment.py`.
- **M** — доступно структурное сопоставление по коду; **C** — только при проверенном контексте/валидации; **GAP** — отсутствует, неоднозначно либо не подтверждена семантика; **META** — не параметр соединения. «M» НЕ означает `sing-box check PASS` или network PASS.
- Документация sing-box по URL ниже — **текущая**, не зафиксированная 1.14.3 schema; каждое спорное поле перепроверять по `sing-box version`, исходникам установленной сборки и `sing-box check`. В частности стандартный upstream справочник транспортов **не перечисляет XHTTP**: расширения sing-box-extended не следует объявлять совместимыми с upstream без проверки.
- Исходный `original_raw` и `params` должны сохраняться; исключение поля в эксперименте сопровождается диагностикой. Не менять `ensure_id()`, дедупликацию, SQLite, production render.
- `EXT` не эталон семантической правильности: он может игнорировать поля и принимать невалидные значения. A/B выявляет расхождения, но не доказывает эквивалентность без анализа.

## Происхождение URI-полей: независимая классификация

Эта классификация **дополняет**, а не заменяет `M/C/GAP/META`. Первые обозначения
описывают происхождение URI-поля; `M/C/GAP/META` — состояние структурного
соответствия с JSON. Ни наличие поля в ссылке, ни успешный `sing-box check`
сами по себе не доказывают сохранение сетевой семантики.

| Код | Класс происхождения | Критерий включения |
|---|---|---|
| `SPEC` | Документировано в спецификации конкретного **share-URI формата** | Указан нормативный документ и точный вариант схемы/формата |
| `EXT` | Документированное расширение реализации | Указаны проект, версия/семейство реализации и источник |
| `LEGACY` | Исторический формат ссылки с устойчивой практикой использования | Указаны формат/реализация и особенности декодирования |
| `OBSERVED` | Поле присутствует в корпусе подписок, но источник семантики не подтверждён | Только инвентаризация; **не** разрешение на mapping |
| `META` | Подтверждённые служебные сведения о ссылке | Не смешивать с неизвестными полями соединения |

**Обязательные атрибуты при дальнейшей разметке каждой строки:**
`uri_family`, `field`, `location` (userinfo/authority/query/fragment/
VMess JSON/nested extra), `origin_class`, `source_ref`, `value_type`,
`applicability` (например, transport/security), `json_mapping_status`
(существующее M/C/GAP/META) и `backend_support` (проверено отдельно).

`SPEC` здесь **не** означает стандарт сетевого протокола. Например,
документация протокола TUIC не делает все встречающиеся `tuic://` query
параметры стандартом URI. Если источник неизвестен, оставляем
`OBSERVED`, а не предполагаем `SPEC`.

### Начальное распределение форматов (не окончательная разметка полей)

| Семейство production URI | Нормативная/историческая база для классификации | Предварительный подход |
|---|---|---|
| VLESS | XTLS/Xray share-link conventions и расширения; проверить конкретный вариант | Размечать базовые поля и extension по отдельным источникам, без объявления всех query keys стандартом |
| VMess | Текущий production VMess **Base64(JSON)** и отдельное VMessAEAD URI proposal | Поля legacy JSON отмечать `LEGACY`; не переносить семантику одноимённых query-полей другого формата |
| Trojan | Базовый `trojan://password@host:port` плюс клиентские transport/TLS extensions | Разделить базовый URI и реализационные расширения |
| Shadowsocks | SIP002 плюс устаревшие формы Base64 | Размечать SIP002 как `SPEC`, прежние варианты как `LEGACY`; `plugin` и `plugin_opts` не объявлять автоматически равнозначными |
| Hysteria2 / hy2 | Документированный Hysteria2 URI и дополнительные параметры клиентов | Официальные URI-поля — `SPEC`, клиентские расширения — `EXT`; `pinSHA256` не путать с uTLS `fp` |
| TUIC | Документация сетевого протокола и URI-конвенции отдельных клиентов | До подтверждения источников query-поля — `EXT` или `OBSERVED`, но не `SPEC` |

Следующий аудит выполняется **в существующих таблицах протоколов**:
добавить для каждого URI-поля класс происхождения и ссылку на документ,
не изменяя пока `M/C/GAP/META` и код конвертера. Неизвестные ключи можно
сохранять и исключать из временного JSON с диагностикой, но это отдельная
политика `best_effort`, а не автоматическое доказательство эквивалентности.
При решении о передаче в JSON учитывать, что названия URI-параметров и
названия структурных полей JSON часто различаются.

## Общая оболочка (для всех шести протоколов)

| URI-источник | JSON outbound | Тип / условие | EXT / PF и риски |
|---|---|---|---|
| `scheme://` | `type` | Enum: `vless`, `vmess`, `trojan`, `shadowsocks`, `hysteria2`, `tuic` | `ss` → `shadowsocks`, `hy2` → `hysteria2`; `type` **в query** — транспорт, не протокол |
| URI authority host, VMess `add` | `server` | hostname/IP, непустой | Строгий разбор IPv6/URL encoding |
| URI authority port, VMess `port` | `server_port` | integer 1…65535 | Не подменять отсутствующий порт фиктивным; HY2 допускает protocol-specific default в EXT, но не распространять на остальные |
| URI fragment `#name`, VMess `ps` | metadata/name, при необходимости JSON `tag` | META | Не влияет на endpoint, не должен становиться top-level vendor field |
| произвольные `Telegram`, рекламные поля | нет | META **только после подтверждения назначения** | EXT VLESS пропускает `Telegram`; PF render отвергал; не обобщать на другие неизвестные поля |
| неизвестные ключи | нет автоматического сопоставления | GAP | Логировать поле, протокол, действие; не считать успешный JSON доказательством эквивалентности |
| дубли одного query key | отказ на ingest | C | `ingest._parse_unique_query` уже запрещает duplicates; VMess JSON требует отдельной политики |
| `original_raw` | нет | provenance | Сохранять исходник verbatim вне JSON |

## VLESS

| URI поле / вариант | JSON назначение | Статус | EXT / PF / ограничения | Происхождение / источник |
|---|---|---|---| --- |
| `UUID@`, `uuid` | `uuid` | M | обязательный идентификатор; нужна UUID validation, без догадки | EXT [V1] |
| `flow` | `flow` | C | `xtls-rprx-vision` поддерживается; EXT распознаёт ограниченные значения; неизвестное — ошибка, не замена | EXT [V1] |
| `encryption=none` | отдельного одноимённого поля в VLESS outbound нет | C | Требовать допустимое explicit value; иные encryption расширения нельзя просто отбрасывать | EXT [V1] |
| `security=tls` / `security=reality` | `tls.enabled`, `tls.reality.enabled` | C | EXT имеет собственную обработку; REALITY требует правильных uTLS/public key semantics | EXT [V1,V2] |
| `sni`, `server_name` | `tls.server_name` | M | алиасы должны обнаруживать конфликт | EXT [V1,V2] |
| `fp`, `client-fingerprint` | `tls.utls.fingerprint` | C | fingerprint uTLS ≠ certificate pin; REALITY без explicit fingerprint не «чинить» добавлением chrome | EXT [V2] |
| `pbk`/`public_key`, `sid`/`short_id` | `tls.reality.public_key`, `short_id` | C | значение и формат проверять; конфликт алиасов → ошибка | EXT [V2] |
| `spx`/`spider_x`, `fm`/`final_mask` | нет проверенного эквивалентного поля | GAP | PF mapper отвергает; в эксперименте нельзя silently drop | OBSERVED [V2] |
| `packetEncoding`, `packet_encoding` | `packet_encoding` | M | проверить допустимые значения: `xudp`, `packetaddr`, empty | EXT [V2] |
| `type`/`net` = `tcp`/`raw` | нет transport object (обычный TCP) | C | `raw` нормализуется только как доказанный алиас при ingest; `headerType` отдельно | EXT [V1] |
| `type=ws` + `path`, `host`, `ed`, `eh` | `transport.type=ws`, `path`, `headers.Host`, `max_early_data`, `early_data_header_name` | C | проверить escaping и HTTP headers | EXT [V1,V2] |
| `type=grpc` + `serviceName` | `transport.type=grpc`, `service_name` | C | aliases `service_name`; timeout требует duration | EXT [V1,V2] |
| `type=http/h2` | `transport.type=http` | C | `host` как массив, `path`, `method`, `headers`; нет автоматической эквивалентности HTTP/2 | EXT [V1] |
| `type=httpupgrade` | `transport.type=httpupgrade` | C | host/path/headers — транспортные поля | EXT [V2] |
| `type=xhttp`, `mode/path/host/extra` | extended `transport.type=xhttp` | GAP | **Не стандартный upstream транспорт в текущем справочнике**; EXT VLESS ожидает Base64URL(JSON) в `extra`, PF mapper — JSON-text: расхождение | EXT [V2] |
| `type=kcp/quic/domainsocket/splithttp` | нет проверенной стандартной реализации | GAP | Отказать, а не преобразовать в TCP; учесть различие upstream/extended | EXT/LEGACY [V1] |

## VMess (Base64 JSON share payload)

| Входное поле VMess | JSON назначение | Статус | EXT / PF / ограничения | Происхождение / источник |
|---|---|---|---| --- |
| `add`, `port`, `id` | `server`, `server_port`, `uuid` | M | обязательные endpoint/ID; неверные port/UUID → ошибка | LEGACY [M1] |
| `aid`, `alterId`, `alter_id` | `alter_id` | C | integer, не угадывать отсутствующее; EXT может игнорировать ошибки `aid` | LEGACY [M1] |
| `scy`, `cipher`, *(contextual)* `security` | `security` | C | VMess cipher ≠ VLESS `security=tls`; не конфликтовать с TLS selector | LEGACY [M1] |
| `tls` + `sni`, `alpn`, `fp` | `tls.enabled`, `server_name`, `alpn`, `utls.fingerprint` | C | explicit value, не восстанавливать из предположений | LEGACY [M1] |
| `net` + `path`, `host`, `type` | `transport` | C | VMess `type` может обозначать header type, а не transport; критично различать от VLESS query | LEGACY [M1] |
| `net=ws` | `transport.type=ws` | M | ранние данные и Host требуют fixtures | LEGACY [M1] |
| `net=grpc` | `transport.type=grpc` | C | serviceName/aliases | LEGACY [M1] |
| `net=h2/http` | `transport.type=http` | C | проверить HTTP request semantics | LEGACY [M1] |
| `global_padding`, `authenticated_length` | одноимённые boolean | C | в legacy VMess URI часто отсутствуют, отсутствие ≠ explicit false | OBSERVED |
| `packetEncoding` | `packet_encoding` | C | зависит от parser implementation | OBSERVED |
| `ps`, `v` | metadata / format version | META/C | `ps` не outbound; `v` версия share payload, проверить формат | META/LEGACY [M1] |
| неизвестные VMess JSON keys | нет | GAP | EXT обычно игнорирует; не считать безопасными без анализа | OBSERVED |

## Trojan

| URI поле | JSON назначение | Статус | EXT / PF / ограничения | Происхождение / источник |
|---|---|---|---| --- |
| `password@` | `password` | M | обязательный пароль | EXT [T1] |
| TLS (protocol-implied), `security`, `sni`, `alpn`, `fp` | `tls.enabled`, `server_name`, `alpn`, `utls` | C | Не превращать явный TLS conflict в успешный конфиг | EXT [T1] |
| `type=ws`, `path`, `host` | `transport.type=ws`, `path`, `headers.Host` | C | EXT поддерживает WS; проверить headers | EXT [T1] |
| `type=grpc`, `serviceName` | `transport.type=grpc`, `service_name` | C | EXT поддерживает gRPC; конфликт алиасов | EXT [T1] |
| `type=http/h2/httpupgrade/xhttp` | зависит от версии и реализации | GAP | Не считать поддержку PF mapper доказательством EXT/standard equivalence | EXT/OBSERVED [T1] |
| `headerType` | none/TCP header semantics | C | принимать только доказанно нейтральные значения | EXT/OBSERVED [T1] |
| vendor fields | нет проверенного JSON назначения | GAP | EXT может проигнорировать, но это не гарантия | OBSERVED |

## Shadowsocks (SIP002 / legacy)

| URI поле | JSON назначение | Статус | EXT / PF / ограничения | Происхождение / источник |
|---|---|---|---| --- |
| userinfo `method:password` | `method`, `password` | M | SIP002 plain/base64 и legacy base64; сохранить ровно однократное URI decoding | SPEC/LEGACY [S1] |
| `plugin=name;opts` | `plugin`, `plugin_opts` | C | Разделять только синтаксические границы SIP002; не терять literal delimiters | SPEC [S1] |
| `plugin_opts`, `plugin-opts` | `plugin_opts` | C | конфликт с уже раскрытым `plugin=...;opts` → диагностировать | OBSERVED |
| `network` | `network` | C | `tcp`/`udp` допустимы; не путать с `type` V2Ray transport | OBSERVED |
| `udp_over_tcp` | `udp_over_tcp` | C | boolean/object по схеме установленного ядра | OBSERVED |
| `multiplex` | `multiplex` | C | JSON object; не считать частью URI SIP002 без подтверждения | OBSERVED |
| `type=tcp`, `headerType=none` | нет собственного SS transport | C | только доказанная render-neutral metadata, не добавлять transport object | OBSERVED |
| неизвестные поля | нет | GAP | EXT SS link handler обрабатывает минимальный набор | OBSERVED [S1] |

## Hysteria2 / hy2

| URI поле | JSON назначение | Статус | EXT / PF / ограничения | Происхождение / источник |
|---|---|---|---| --- |
| userinfo / `auth` | `password` | C | требуется отсутствие противоречий `password/auth` | SPEC [H1] |
| authority порт / `mport`, `ports`, `server_ports` | `server_port` или `server_ports` | C | server_ports — диапазоны, JSON `2080:3000`; порт hopping без потерь | SPEC/EXT [H1] |
| `hop_interval`, `hop_interval_max` | одноимённые duration | C | число и единицы нельзя угадывать | OBSERVED |
| `up`/`down`, `up_mbps`/`down_mbps` | integer Mbps | C | PF отвергает нецелое Mbps; EXT может проигнорировать ошибку | OBSERVED [H1: explicitly excluded] |
| `obfs`, `obfs-password` | `obfs.type`, `obfs.password` | C | salamander и корректность пароля | SPEC [H1] |
| `obfs_min_packet_size`, `obfs_max_packet_size` | `obfs.min_packet_size`, `max_packet_size` | C | проверить ограничения | EXT [H1] |
| `sni`, `alpn`, `insecure` | `tls.server_name`, `alpn`, `insecure` | C | применяется static security gate; insecure TLS не принимать автоматически | SPEC/EXT [H1] |
| `fingerprint`, `pinSHA256` | certificate pinning, **не** `tls.utls.fingerprint` | GAP | Не подменять pin браузерным fingerprint; точное представление зависит от типа pin | SPEC/EXT [H1] |
| `fp`, `client-fingerprint` | `tls.utls.fingerprint` | C | только явное uTLS значение | EXT [H1] |
| `network`, QUIC extensions, `bbr_profile`, `realm` | `network`, QUIC/realm objects | GAP/C | JSON core capabilities могут превосходить EXT URI handler; нужны проверки по версии | EXT/OBSERVED [H1] |
| `fastopen`, `realm-opts` | нет проверенного URI mapping | GAP | текущий PF mapper отказывает | EXT/OBSERVED [H1] |

## TUIC

| URI поле | JSON назначение | Статус | EXT / PF / ограничения | Происхождение / источник |
|---|---|---|---| --- |
| `UUID:password@` | `uuid`, `password` | M | обязательный UUID; password проверять отдельно | OBSERVED [U1: not URI specification] |
| `congestion_control` / `congestion-controller` | `congestion_control` | C | проверить разрешённые `cubic/new_reno/bbr` | OBSERVED [U2] |
| `udp_relay_mode` | `udp_relay_mode` | C | не путать с `udp_over_stream` | OBSERVED [U2] |
| `udp_over_stream` | `udp_over_stream` | C | EXT может очищать relay mode при true, требуются fixtures | OBSERVED [U2] |
| `zero_rtt_handshake` / `reduce-rtt` | `zero_rtt_handshake` | C | строгий bool | OBSERVED [U2] |
| `heartbeat`, `heartbeat_interval` | `heartbeat` duration | C | секунды vs миллисекунды; не допускать конфликта | OBSERVED [U2] |
| `sni`, `alpn`, `insecure` | `tls` | C | static security gate | OBSERVED [U2] |
| `fingerprint` (certificate) | **не** `tls.utls.fingerprint` | GAP | различить с `fp` (uTLS) | OBSERVED [U1] |
| `token` | TUIC v4 legacy auth | GAP | текущий PF mapper отвергает; не трактовать как TUIC v5 | LEGACY [U1] |
| `network`, QUIC параметры | `network` / QUIC fields | C | проверка версии ядра и схемы | OBSERVED [U2] |


### Поимённая инвентаризация URI-полей (версия 0.2)

В этой таблице **расположение поля и класс относятся к самому полю**, а не к
одноимённому JSON-ключу ядра. Записи сгруппированы только там, где одинаковы
источник и смысл. `OBSERVED` означает «встречается в конфигурациях или
существующем PF mapper, но надёжный нормативный URI-источник пока не закреплён».
`EXT` не гарантирует поддержку в установленном `sing-box`. Обозначение
`[схема]` ниже не подразумевает ввод новых production-схем.

#### VLESS — query URI и userinfo

| Поле / алиасы | Где | Класс | Источник / граница применимости |
|---|---|---|---|
| `uuid` (UUID в userinfo) | userinfo | EXT | [V1], обязательный идентификатор; в checkpoint хранится как `uuid` |
| `encryption`, `flow` | query | EXT | [V1]; значения и требования зависят от версии VLESS |
| `type`, `host`, `path` | query | EXT | [V1], транспортно-зависимые значения |
| `security`, `sni`, `alpn` | query | EXT | [V1], TLS/XTLS; `reality` — позднее расширение [V2] |
| `fp` | query | EXT | [V2], uTLS client fingerprint |
| `pbk`, `sid`, `spx`, `pqv` | query | EXT | [V2], REALITY; `spx` не объявлять безвредным metadata |
| `serviceName`, `mode` | query | EXT | [V1,V2], транспортно-зависимо; `mode` неоднозначен вне типа транспорта |
| `extra` | query | EXT | [V2], XHTTP extra; способ кодирования сверять по конкретной версии экспортёра |
| `ed`, `eh` | query | EXT | [V2], WS early data; уточнение по источнику версии требуется |
| `packetEncoding` | query | EXT | [V2], допустимые значения валидировать отдельно |
| `server_name`, `client-fingerprint`, `public_key`, `short_id` | query | OBSERVED | Локальные алиасы PF mapper; требуются URI-источники для точного написания |
| `authority`, `headerType`, `method`, `headers` | query | OBSERVED | Зависимые от транспорта; одного наличия native JSON-поля недостаточно |
| `pcs`, `vcn`, `ech`, `fm` | query | EXT/OBSERVED | Xray-specific расширения; для каждого поля требуется версия экспортёра [V2] |
| `spider_x`, `final_mask`, `net`, `network` | query | OBSERVED | Алиасы/расширения PF; не часть доказанного базового VLESS URI |
| `allowInsecure`, `insecure`, `disable_sni` | query | EXT/OBSERVED | Настройки TLS, риск смены security semantics; проверить конкретный клиент |
| `cs` | query | OBSERVED | TLS cipher suites selector in some share-link exporters; Xray TLS config `cipherSuites` is a colon-separated string [C1,C2]. Не VLESS `encryption`, не `fp`. URI-нормативность не доказана |
| `x_padding_bytes`, `support-x25519mlkem768` | query / config.params | OBSERVED | Реальные поля checkpoint: XHTTP padding range (18) и REALITY hybrid key-share hint (9). Значимы для соединения, не metadata; при неподдерживаемом mapping нужен GAP [XH1,PQ1] |
| `note`, `password`, `allowinsecure`, `pinSHA256`, `packet-encoding`, `udp` | config.params после ingest | OBSERVED | Зафиксированы аудитом 8 848; `note` — кандидат metadata, но не автоматически безопасное для соединения поле; `password` в VLESS требует отдельного анализа |

#### VMess — legacy Base64(JSON), а не query URI

| Поле / алиасы | Где | Класс | Источник / граница применимости |
|---|---|---|---|
| `v`, `ps` | JSON внутри Base64 | META/LEGACY | [M1], версия формата и имя |
| `add`, `port`, `id` | JSON внутри Base64 | LEGACY | [M1], endpoint/UUID |
| `aid`, `scy` | JSON внутри Base64 | LEGACY | [M1], alterId и шифр |
| `net`, `type`, `host`, `path` | JSON внутри Base64 | LEGACY | [M1]; `type` — TCP header/disguise, **не** transport selector |
| `tls`, `sni`, `alpn`, `fp`, `insecure` | JSON внутри Base64 | LEGACY | [M1], TLS и проверка сертификата |
| `vcn`, `pcs` | JSON внутри Base64 | LEGACY | [M1], дополнительные условия сертификата; нельзя потерять молча |
| `global_padding`, `authenticated_length`, `packetEncoding` | JSON внутри Base64 | OBSERVED | Есть в PF mapper/native schema, но [M1] не доказывает все эти share-ключи |
| `security`, `cipher`, `alterId`, `network`, `uuid` | JSON внутри Base64 | OBSERVED | Алиасы PF, не приравнивать автоматически к исходным [M1] |
| `vmess://UUID@host:port?...` | **другой формат** | EXT | [V1], предложение VMessAEAD URI; **не** смешивать с [M1] |
| `cs` | JSON внутри Base64 | OBSERVED | В VMess legacy share JSON найдено в 126 записях. Нельзя выводить нормативность VMess JSON из документации Xray `cipherSuites`; [C1,C2] подтверждают назначение лишь как TLS expansion |
| `pqv`, `xhttp_extra`, `mux`, `muxConcurrency` | JSON внутри Base64 / config.params | OBSERVED | Наблюдаемые VMess поля (5, 1, 1, 1); назначение `pqv` без подтверждения нельзя автоматически приравнять к VLESS `pqv`; XHTTP и multiplex требуют контекста [PQ1,XH1] |
| `name`, `skip-cert-verify`, `serviceName`, `ech`, `echConfigList` | JSON внутри Base64 / config.params | OBSERVED | Аудит 8 848: варианты полей и расширения; `name` кандидат META, остальные нельзя молча отбрасывать |

#### Trojan — base URI и клиентские расширения

| Поле / алиасы | Где | Класс | Источник / граница применимости |
|---|---|---|---|
| `password` | userinfo | EXT | [T1], пароль Trojan |
| `sni`, `peer`, `alpn`, `fp`, `allowInsecure` | query | EXT | [T1], TLS; `peer` означает SNI в данном формате |
| `security`, `type`, `host`, `path`, `serviceName` | query | EXT | [T1], security/WS/gRPC/HTTP transport |
| `pbk`, `sid`, `ech` | query | EXT | [T1], REALITY/ECH клиентские расширения |
| `extra`, `mode`, `pcs`, `fm` | query | OBSERVED | Не подтверждены ссылкой [T1] как универсальные поля Trojan URI |
| `headerType`, `headers`, `authority`, `net`, `network` | query | OBSERVED | Нужна точная спецификация транспортного расширения |
| `cs` | query | OBSERVED | TLS cipher suites; наблюдается в 2 Trojan URI. [C1] описывает семантику Xray `cipherSuites`, [C2] — конвенцию экспорта `cs`; это не универсальный Trojan URI стандарт |
| `insecure`, `allow_insecure`, `allowinsecure`, `spx`, `flow`, `encryption`, `ed`, `eh`, `ws`, `Host`, `note` | query / config.params | OBSERVED | По аудиту 8 848; `insecure` — 466 конфигураций; распознавание не устанавливает допустимые значения и эквивалентность; `note` кандидат META |

#### Shadowsocks — SIP002 и legacy

| Поле / алиасы | Где | Класс | Источник / граница применимости |
|---|---|---|---|
| `method`, `password` | userinfo | SPEC | [S1], plaintext percent-encoded либо Base64URL по правилам семейства шифра |
| `host`, `port` | URI authority | SPEC | [S1], адрес сервера |
| `plugin` | query | SPEC | [S1], единый параметр с вложенными настройками и экранированием |
| `#tag` | fragment | META/SPEC | [S1], отображаемое имя |
| `ss://Base64(method:password@host:port)` | legacy форма | LEGACY | [S1], предшественник SIP002 |
| `plugin_opts`, `plugin-opts` | query | OBSERVED | Не отдельные нормативные параметры SIP002 |
| `network`, `udp_over_tcp`, `multiplex` | query | OBSERVED | Не определены SIP002; схема native JSON этого не меняет |
| `type`, `headerType` | query | OBSERVED | Не часть SIP002; SS transport нельзя заимствовать из VLESS |
| `note` | config.params после ingest | OBSERVED | По имени похоже на заметку, но источник и безопасность исключения ещё не подтверждены; не часть SIP002 |

#### Hysteria2 / hy2 — официальный share URI

| Поле / алиасы | Где | Класс | Источник / граница применимости |
|---|---|---|---|
| `hysteria2://`, `hy2://` | scheme | SPEC | [H1], обе формы указаны официально |
| `auth` | userinfo | SPEC | [H1], percent encoding; допускается userpass |
| `hostname[:port]`, диапазоны портов | authority | SPEC | [H1], по умолчанию порт 443; multi-port в authority |
| `obfs`, `obfs-password` | query | SPEC | [H1], значения обфускации зависят от версии |
| `sni`, `insecure`, `pinSHA256`, `ech` | query | SPEC | [H1], TLS; pinSHA256 — certificate pin, не uTLS |
| `#name` | fragment | META/SPEC | [H1], имя |
| `mport`, `ports`, `server_ports` | query | OBSERVED | Алиасы port hopping; не заменяют нормативный multi-port authority |
| `hop_interval`, `hop_interval_max` | query | OBSERVED | Настройки hopping вне перечисления [H1] |
| `up`, `down`, `upmbps`, `downmbps` | query | EXT/OBSERVED | [H1] **предписывает не включать bandwidth** в переносимую URI |
| `fp`, `client-fingerprint`, `fingerprint` | query | OBSERVED | uTLS и сертификатный pin — разные значения; не отождествлять |
| `alpn`, `fastopen`, `realm`, `realm-opts`, `bbr_profile`, `network` | query | OBSERVED | Не определены как поля базового `hysteria2://` в [H1] |
| `hysteria2+realm://` | **другая схема** | SPEC, вне production | [H1], не включать автоматически в `hysteria2://` ingest |
| `password`, `security`, `fm` | config.params после ingest | OBSERVED | `password` — внутреннее представление auth в checkpoint, НЕ утверждение о нормативном query `password`; `security`/`fm` — не подтверждённые H1 расширения |

#### TUIC v5 — URI-конвенция, не формальный URI-стандарт

| Поле / алиасы | Где | Класс | Источник / граница применимости |
|---|---|---|---|
| `uuid`, `password` (как `uuid:password`) | userinfo | EXT/OBSERVED | Имеющаяся `tuic://`-конвенция; [U1] не задаёт синтаксис share URI |
| `host`, `port`, `#name` | authority/fragment | EXT/OBSERVED | URI-оболочка; точное правило URI-экспортёра не установлено |
| `congestion_control`, `congestion-controller` | query | OBSERVED | Семантика JSON известна по [U2], происхождение URI не доказано |
| `udp_relay_mode`, `udp-relay-mode` | query | OBSERVED | [U2] определяет JSON; не использовать как URI-спецификацию |
| `udp_over_stream`, `udp-over-stream` | query | OBSERVED | [U2], проверить конфликт с `udp_relay_mode` |
| `zero_rtt_handshake`, `zero-rtt-handshake`, `reduce-rtt` | query | OBSERVED | JSON/клиентские алиасы; не доказывают `tuic://` формат |
| `heartbeat`, `heartbeat_interval`, `heartbeat-interval` | query | OBSERVED | Клиентские продолжительности; единицы могут отличаться |
| `sni`, `alpn`, `insecure`, `allow_insecure`, `fp` | query | OBSERVED | TLS-конвенции; требуется источник точной URI-разметки |
| `fingerprint` | query | OBSERVED | Может обозначать certificate pin; нельзя подставлять в `tls.utls` |
| `token` | query | LEGACY/OBSERVED | Связано с TUIC v4 в предыдущем аудите; не трактовать как v5 |

**Проверки перед использованием реестра:** поля с `OBSERVED` требуют
источника/fixtures конкретного экспортёра; алиасы надо проверять
на совпадение типов и значений; вложенные настройки XHTTP рассматриваются
отдельно. Полнота этого реестра относится к текущим строкам документа и
известным URI-соглашениям, а не ко всем возможным расширениям клиентов.

### Ссылки классификации происхождения URI (проверены 2026-11-05)

- **[V1]** [XTLS/Xray-core #716 — VMessAEAD / VLESS share-link proposal](https://github.com/XTLS/Xray-core/discussions/716). Это **предложение URI**, а не общеобязательный стандарт каждого Xray-расширения.
- **[V2]** [Material Xray — VLESS share-link conventions](https://materialxray.app/docs/reference/share-links/). Документация конкретной реализации; поля XHTTP/REALITY и прочие расширения должны иметь версионный контекст.
- **[M1]** [v2rayN Wiki — Description of VMess share link](https://github.com/2dust/v2rayN/wiki/Description-of-VMess-share-link). Документирован именно legacy формат `vmess://Base64(JSON)`, не VMessAEAD URL с query.
- **[T1]** [Potatso — Trojan share URI](https://docs.potatso.com/protocols/trojan/). Описывает клиентское представление `trojan://` и Xray-совместимые дополнения; это не спецификация сетевого Trojan-протокола.
- **[S1]** [Shadowsocks — SIP002 URI scheme](https://shadowsocks.org/doc/sip002.html). Нормативное описание ссылки, `plugin`, структуры userinfo и правил percent/Base64URL encoding.
- **[H1]** [Hysteria2 — official URI Scheme](https://v2.hysteria.network/docs/developers/URI-Scheme/). Нормативные поля `obfs`, `obfs-password`, `sni`, `insecure`, `pinSHA256`, `ech`; bandwidth исключён намеренно.
- **[C1]** [Xray TLS transport documentation](https://xtls.github.io/en/config/transports/tls.html): `cipherSuites` задаёт разделённый `:` список TLS cipher suite names; это описание Xray JSON, **не** стандарт URI-поля `cs`.
- **[C2]** [3x-ui issue / PR #6825](https://github.com/MHSanaei/3x-ui/pull/6825): предложение экспортировать TLS `cipherSuites` в share links как `cs` (VLESS/Trojan/VMess). Источник подтверждает используемую конвенцию, но не доказывает универсальную нормативность и не гарантирует включение изменений в релиз.
- **[U1]** [TUIC protocol specification](https://github.com/tuic-protocol/tuic/blob/master/SPEC.md). Описывает **сетевой протокол**, а не нормативную `tuic://`-схему; URI-параметры нельзя считать SPEC на основании этого источника.
- **[U2]** [sing-box TUIC outbound](https://sing-box.sagernet.org/configuration/outbound/tuic/). Описывает **native JSON** TUIC, а не поля `tuic://`; в таблице такие поля предварительно `OBSERVED` до нахождения документации конкретного URI-экспортёра.

**Предел доказательности:** ссылка в последнем столбце удостоверяет документированное
семейство/соглашение, но не обязательно каждое перечисленное через запятую
имя алиаса. Для строки с `SPEC/EXT` или `EXT/OBSERVED` нужно применять
следующий детальный реестр по отдельным именам; смешанный статус намеренный.
При отсутствии явного подтверждения конкретного написания поле остаётся
`OBSERVED`; сам факт поддержки в native JSON не подтверждает URI-семантику.

## Транспорт и TLS: ключевые перекрёстные несовместимости

| Семейство | Типичная URI запись | Стандартный JSON | Особый риск |
|---|---|---|---|
| TLS SNI | `sni`, `server_name` | `tls.server_name` | alias conflict; empty vs absent |
| TLS ALPN | `alpn=h2,http/1.1` | `tls.alpn: [..]` | список и порядок |
| uTLS | `fp=chrome` | `tls.utls: {enabled:true,fingerprint:"chrome"}` | не равен certificate fingerprint |
| REALITY | `security=reality&pbk=...&sid=...` | `tls.reality` | `fp` нельзя домысливать |
| WS | `type=ws&path=...&host=...` | `transport.type=ws`, path, headers | ранние данные, заголовки |
| gRPC | `type=grpc&serviceName=...` | `transport.type=grpc` | timeout/duration |
| HTTP/H2 | `type=http/h2` | `transport.type=http` | не каждый HTTP/2 URI эквивалентен |
| HTTPUpgrade | `type=httpupgrade` | `transport.type=httpupgrade` | Host/headers |
| XHTTP | `type=xhttp&extra=...` | **extended-specific**, не считать upstream стандартом | Base64URL(JSON) в EXT и JSON-text в PF |
| mKCP/QUIC/DomainSocket | `type=kcp/quic/ds` | зависит от upstream/extended | upstream справочник исключает mKCP/DomainSocket, QUIC перечисляет |
| certificate pin | `fingerprint`, `pinSHA256` | не выводить в uTLS автоматически | разные алгоритмы/формы pin |

## Семантический контракт полей: типы, значения, зависимости (этап 1)

Это **отдельный от классификации происхождения** слой спецификации.
Он описывает проверку на границе URI → protocol-specific model. Обозначения:

- **P** — правило подтверждается указанным форматом или структурой URI;
- **V** — правило нужно сверить с указанной версией share-формата/целевого backend;
- **G** — gate отказа: нельзя создавать видимость работоспособного соединения
  заменой неизвестного, некорректного или неподдерживаемого значения;
- **`absent` ≠ `""` ≠ `null`**; преобразование допустимо только по
  документированной семантике конкретного поля и формата;
- исходный `original_raw` и `params` сохраняются; никакой автоматической
  нормализации источника при аудите.

Следующие таблицы **не являются реализацией** и не утверждают, что все поля
поддерживаются `sing-box 1.14.3-extended`. Статус `V` — открытая проверка,
не разрешение молча исключать поле.

### Общая оболочка и аутентификация

| Формат / поле | Тип исходника | Допустимость / значение | Зависимости / конфликты | Проверка |
|---|---|---|---|---|
| Все URI: hostname, port | URI authority | Host непустой; explicit port 1–65535; IPv6 в квадратных скобках | Отсутствие порта не заменять произвольным, у Hysteria2 есть собственный default | P/G |
| VLESS: `uuid` | UUID в userinfo | Формально корректный UUID | Не подставлять UUID из имени ссылки | P/G [V1] |
| VMess legacy: `id`, `aid` | строки/числа внутри Base64(JSON) | `id` UUID; `aid` целое без дробной части; тип `aid` string/number проверять | `net` задаёт транспорт, `type` — header type | P/V [M1] |
| Trojan: `password` | userinfo | Непустой пароль после строго одного URI decode | Не путать с query password | P/G [T1] |
| SS: `method`, `password` | userinfo, SIP002/legacy | Непустые; декодирование зависит от SS URI-формы/шифра | Плагин `plugin` — отдельная зависимая конфигурация | P/V [S1] |
| Hysteria2: auth/userinfo | userinfo | По H1; различать исходный userinfo и ingest `params.password` | `obfs-password` не равно паролю сервера | P/V [H1] |
| TUIC: `uuid:password` | userinfo | UUID + password; синтаксис — соглашение URI экспортёра | Нельзя подменять v5 `token` из v4 | V/G [U1] |

### TLS, REALITY и сертификаты

| Протокол / поля | Тип значений | Семантика / допустимые значения | Зависимости / конфликты | Проверка |
|---|---|---|---|---|
| VLESS/Trojan: `security` | selector string | `none`, `tls`, `reality` — проверить по текущей реализации; неизвестное значение не превращать в `none` | REALITY: `pbk` и контекст `sid`; TLS-свойства нельзя оставлять при неактивном TLS без разбора | V/G [V1,V2,T1] |
| VLESS: `encryption` | string | Базовый `none`; иное значение — не «пустая метка», а возможное расширение | Не отбрасывать неизвестное encryption | P/G [V1] |
| VMess: `scy` | enum string | Допустимый cipher список сверять с VMess и target backend | Не путать с `security=tls` других URI | V/G [M1] |
| `sni`, `server_name` | string | Точное значение имени, включая регистр/escaping по спецификации | При конфликтующих алиасах — отказ; не брать SNI из чужого поля автоматически | V/G |
| `alpn` | string/list по формату | Упорядоченный список протоколов; пустые элементы требуют отдельной проверки | TLS контекст; не сортировать и не дедуплицировать без доказательства | V |
| `fp` / `client-fingerprint` | string | uTLS client fingerprint, **не certificate pin** | `fp` не универсален для всех протоколов; недокументированное значение — отказ/gap | V/G [V2] |
| `pbk` / `public_key` | encoded public key | REALITY public key с форматом, размером и кодированием, установленными Xray | `security=reality`; конфликт алиасов — отказ; не придумывать отсутствующие значения | V/G [V2] |
| `sid` / `short_id` | hex-like string | Формат и допустимая длина по REALITY; пустое значение не равно отсутствующему без доказательства | Только REALITY | V/G [V2] |
| `spx`, `pqv`, `fm` | extension string | Специфичные REALITY/FinalMask расширения | Пока `GAP` или ограниченный mapper — явно фиксировать, не отбрасывать как META | V/G [V2] |
| VLESS/VMess/Trojan: `cs`, `cipher_suites`, `cipher-suites` | colon-separated cipher list / URI string | Относится к TLS cipher suites; не `fp` (uTLS) и не VMess `scy`; кодирование/имена cipher suite не переписывать | Применимо только при реально активном TLS и при поддержке backend; пустое значение/список и конфликты алиасов не исправлять | V/G [C1,C2] |
| `allowInsecure`, `insecure`, `skip-cert-verify` | bool-like | Синтаксис true/false **зависит от формата**; `""` не равен `true` | Отключает/меняет TLS verification; конфликт с проверкой pin и политикой безопасности | V/G |
| Hysteria2: `pinSHA256` | certificate pin | Формат SHA-256 pin по официальному H1 | **Не** `tls.utls.fingerprint`; `fp` не синоним | P/G [H1] |
| `pcs`, `vcn`, `ech` | extension string/encoded | Pin/ECH/verification специфичны для клиента; нужны версия и семантика | Не переинтерпретировать pin сертификата как uTLS | V/G |

### Транспорты VLESS / Trojan и VMess

| Поле / контекст | Тип | Семантика / значения | Зависимости и конфликт | Проверка |
|---|---|---|---|---|
| VLESS/Trojan: `type` | selector string | `tcp`/`raw`, `ws`, `grpc`, `http`/`h2`, `httpupgrade`, `xhttp`; дополнительные — только при наличии подтверждённого mapping | Неизвестное значение нельзя заменять TCP | V/G [V1,V2,T1] |
| VMess: `net` | selector string | Значение transport независимо от VMess `type` | `net` ≠ `type` и не может замещать его | P/G [M1] |
| VMess: `type` | header/disguise string или null | `none` — кандидат нейтрального header; другие требуют документированного mapping | `null` в реальных JSON и отсутствие `type` требуют отдельной проверки | V/G [M1] |
| WS: `path`, `host` | strings | HTTP path и Host header; порядок/декодирование URL не менять | Только `type=ws`/VMess `net=ws`; пустой path/Host анализировать отдельно | V |
| WS: `ed`, `eh` | nonnegative integer/text | Early data size и header name; значения и диапазон проверить | Только WS; не переносить в unrelated transport | V/G [V2] |
| gRPC: `serviceName`, `service_name` | string | Service name; percent-encoding и конфликт алиасов | Только gRPC; `mode` интерпретировать лишь с контекстом транспорта | V/G |
| HTTP/H2: `host`, `path`, `headers`, `method` | string/list/object по формату | Структуры HTTP transport; не преобразовывать строку заголовков в dict без описанного кодирования | Только HTTP; нельзя автоматически объявить H2 эквивалентом произвольного HTTP | V/G |
| XHTTP: `mode`, `path`, `host` | string | Назначение, разрешённые значения и defaults сверить с версией XHTTP | Только XHTTP; `mode` другого транспорта — отдельное поле | V/G [V2] |
| XHTTP: `extra` | encoded nested JSON | Различать JSON-text и Base64URL(JSON) по документированному формату; валидировать вложенную схему | Пустой extra ≠ `{}`; неизвестные вложенные поля не «исправлять» | V/G [V2] |
| TCP: `headerType` | header selector | `none`/empty — только после проверки транспортного соглашения | Non-neutral disguise требует собственный transport mapping | V/G |
| `packetEncoding` | enum string | Например `xudp`/`packetaddr`, точный enum по ядру | Protocol-specific outbound, не transport `type` | V/G |

### Shadowsocks, Hysteria2 и TUIC: дополнительные зависимости

| Формат / поле | Тип | Условия и конфликт | Проверка |
|---|---|---|---|
| SS `plugin` | SIP002 encoded name/options | Опции извлекать по синтаксису SIP002; отдельно `plugin_opts` не сливать без проверки совпадения | P/G [S1] |
| SS `network`, `udp_over_tcp`, `multiplex` | extension | Не являются нормативными SIP002 query keys; не считать поддержанными из-за имени JSON поля | V/G |
| HY2: authority port ranges | URI authority | Правила hopping и default port по H1; `mport`/query aliases не приравнивать автоматически | P/G [H1] |
| HY2: `obfs`, `obfs-password` | enum + string | Пароль обфускации применим только к соответствующему `obfs`; неизвестный алгоритм — отказ | P/V [H1] |
| HY2: `up`, `down`, `up_mbps` | bandwidth values | Расширения клиента; официальный URI H1 не переносит bandwidth, numeric units не угадывать | V/G [H1] |
| TUIC: `congestion_control` | enum string | Известные варианты target JSON сверять с версией ядра; URI aliases отдельно | V/G [U2] |
| TUIC: `udp_relay_mode`, `udp_over_stream` | enum / boolean | Возможный конфликт настроек UDP; не отдавать противоречивую конфигурацию без явного правила | V/G [U2] |
| TUIC: `zero_rtt_handshake`, `reduce-rtt` | bool-like | URI-алиасы и security последствия 0-RTT проверять по версии клиента | V/G [U2] |
| TUIC: `heartbeat`, `heartbeat_interval` | duration | Не угадывать единицы при алиасах; проверять соответствие schema | V/G [U2] |

### Непосредственно наблюдаемые типы в `03-safe.jsonl`

По аудиту `proxyfilter-uri-provenance-audit-v2.json` (8 848 записей):

| Протокол | Поле | Фактический Python/JSON type | Последствие для следующего этапа |
|---|---|---|---|
| VMess | `aid` | string × 524; number × 22 | Поддерживать оба представления только если значение валидно; не принимать дробные/нецифровые строки |
| VMess | `v` | string × 509; null × 31 | `v` — версия share JSON; null не подменять версией без доказательства |
| VMess | `type` | string × 507; null × 31 | Проверить null/header semantics отдельно от `net` |
| VMess | `host` | string × 528; null × 6 | Различать отсутствующее/пустое/null |
| VMess | `skip-cert-verify` | boolean × 6 | Alias не следует преобразовывать через `bool("false")` |
| VLESS | `headerType` | string × 1 618 | Высокий приоритет: выяснить распределение значений и транспортов |
| VLESS | `extra` | string × 249 | Высокий приоритет: вложенный XHTTP schema и encoding |
| VLESS | `spx` | string × 372 | Проверить REALITY semantic loss, не считать metadata |
| Trojan | `headerType` | string × 408 | Проверить non-neutral disguise и связь с transport |
| Hysteria2 | `security` | string × 38 | Не нормативное поле H1; определить происхождение/условия |

### Выявленное поле `cs`: аудит 2026-11-05

Локальный запуск `--resolve-hash` подтвердил SHA-256 ключа
`3b8b91c75627bee566dcb88f4805901b20a3eab2520bcff8d26c87157a035026`:

| Протокол | Количество в checkpoint |
|---|---:|
| VLESS | 45 |
| VMess (legacy JSON) | 126 |
| Trojan | 2 |
| **Итого** | **173** |

Предполагаемая семантика — **TLS cipher suites**; это подтверждено
[Xray TLS config][C1] и конвенцией `cs` в [C2]. При этом для VMess
legacy Base64(JSON) документированность конкретного поля не доказана.
Классификация во всех трёх таблицах остаётся `OBSERVED` до подтверждения
официального URI-формата/экспортёра. В `proxyfilter/singbox_backend.py`
уже имеется mapping `cs`/`cipher_suites`/`cipher-suites` →
`tls.cipher_suites`, но успешная генерация не доказывает поддержку
целевой сборкой и не гарантирует сохранение TLS-поведения.

Рекомендуемые проверки перед native mapping: корректный список cipher
suite names, правила значения `""`, активный TLS, несовместимые aliases,
TLS 1.3 особенности и поведение с uTLS fingerprint. **Не** переносить
это поле в VMess `scy`, `fp` или в metadata. Никакой silent drop.

### Результат локального раскрытия оставшихся UNLISTED имён

Вывод после семантического аудита (8 848 записей, 75 вхождений)
предоставлен локально 2026-11-05. Значения параметров и URI не исследовались.

| Семейство | Имя → количество | Предварительная категория |
|---|---|---|
| SS | `prefix` 3; `Telegram` 1; `POST` 1 | `prefix` может быть расширением, два остальных — невалидные или необычные query names / экспортер: требуют raw URI проверки |
| Trojan | `wspath` 3; `headertype` 2 | Возможные транспортные алиасы; **не** приравнивать автоматически к `path` и `headerType` без transport-specific evidence |
| VLESS | `x_padding_bytes` 18; `support-x25519mlkem768` 9 | XHTTP padding; REALITY hybrid key-share compatibility — семантически значимы [XH1,PQ1] |
| VLESS | `Telegram` 12; `Telegram🇨🇳WangCai2` 1 | Похожи на ошибочное размещение текстовых меток в query; без оригинального URI нельзя отличить мусор от vendor-параметров |
| VLESS | `headertype` 2; `pool` 2; `al` 1; `fragment` 1 | Возможные алиасы, XHTTP/pooling и fragmentation extension; недоказанная семантика. **Не** классифицировать как META |
| VMess | `pqv` 5; `xhttp_extra` 1; `mux` 1; `muxConcurrency` 1 | Предположительно REALITY/XHTTP и multiplex; зависимость от VMess legacy export; неизвестные значения и mapping |
| VMess | `test_name` 2; `serverDescription` 1; `nation` 1; `batch` 1 | Вероятные метаданные, но принадлежность к metadata по одному имени не доказана |
| VMess | `echServerKeys` 1; `fakehost_domain` 1; `interval` 1; `length` 1; `packets` 1; `serverPort` 1 | Возможные ECH, TLS fragmentation или legacy serializer extensions. `serverPort` не использовать как authority port без явного правила |

**Подсчёт:** SS 5, Trojan 5, VLESS 46, VMess 19 = 75
вхождений. В отдельных строках классификационной матрицы теперь
зарегистрированы только распознанные имена XHTTP/REALITY и явно
помеченные неизвестной семантики VMess extension. Это уменьшит
`UNLISTED` в будущем прогоне, но **не улучшит mapper** само по себе.

- **[XH1]** [Hiddify sing-box XHTTP transport reference](https://hiddify.com/core/sing-box/features/transports/xhttp/): `x_padding_bytes` — диапазон длины XHTTP padding, не декоративная метка. Способ экспортирования через URI varies by client.
- **[PQ1]** [3x-ui REALITY share-link compatibility](https://github.com/MHSanaei/3x-ui/blob/main/docs/content/docs/en/config/reality.mdx): `support-x25519mlkem768` передаётся как необязательный hint в VLESS URI; это не универсальный нормативный параметр URI. См. также [issue #6555](https://github.com/MHSanaei/3x-ui/issues/6555) и [issue #6730](https://github.com/MHSanaei/3x-ui/issues/6730).

**Критерий исправления ingest:** если ключ явно похож на ошибочную
текстовую метку (`Telegram`, `POST`), сначала проверить исходный
`original_raw` и правила разбора URI. Нельзя удалять такие поля или
исправлять URI без доказательства ошибки upstream, поскольку действующая
политика ingest — сохранять неизвестные параметры и исходник verbatim.

### Разрешение оставшегося неизвестного имени локально

Отчёт v2 содержит 248 вхождений `UNLISTED` (VLESS 91, VMess 145,
Trojan 7, Shadowsocks 5). Один и тот же SHA-256 ключа встречается
**173 раза** (VLESS 45, VMess 126, Trojan 2):

```text
sha256:3b8b91c75627bee566dcb88f4805901b20a3eab2520bcff8d26c87157a035026
```

Отчёт **не содержит обратимого исходного имени**. Новая опция
`tools/audit_uri_provenance.py --resolve-hash` локально пересчитывает
SHA-256 **только от имён** полей `config.params`; совпавшие имена и
частоты выводятся в терминал, значения полей, `original_raw` и адреса
серверов не выводятся. Результат не записывается в JSON audit и не
изменяет checkpoint.

```bash
python3 tools/audit_uri_provenance.py \
  --checkpoint ../data/work/03-safe.jsonl \
  --resolve-hash 3b8b91c75627bee566dcb88f4805901b20a3eab2520bcff8d26c87157a035026
```

Возможна конфиденциальность **самих имён ключей**; результат предназначен
только для локальной проверки. До его получения нельзя утверждать, какое
именно поле породило этот digest. Другие UNLISTED ключи исследовать по
убыванию частоты. Отсутствие TUIC в корпусе требует отдельных fixture.

## Аудит полей реальных URI по матрице

Для текущего checkpoint `data/work/03-safe.jsonl` создан отдельный,
**read-only** инструмент `tools/audit_uri_provenance.py`. Он не использует
устаревший вручную составленный `KNOWN` из `tools/audit_uri_fields.py`,
а извлекает поимённые классы непосредственно из раздела
«Поимённая инвентаризация URI-полей» **этого документа**. Если структура
матрицы исчезнет или будет повреждена, инструмент остановится вместо
незаметного fallback на список полей.

Из каталога `app/`:

```bash
python3 -m unittest tests.test_audit_uri_provenance -v
python3 tools/audit_uri_provenance.py \
  --checkpoint ../data/work/03-safe.jsonl \
  --output /tmp/proxyfilter-uri-provenance-audit.json
```

Отчёт содержит для каждого протокола: число строк; список полей и частоту
встречаемости; классы `SPEC/EXT/LEGACY/OBSERVED/META`, включая составные;
ссылочные коды источников; количество вхождений по классам; и типы значений.
При этом **значения параметров, URI, серверы, порты, UUID и пароли не
сохраняются**. Если имя отсутствует в матрице, вместо самого имени
выводится `sha256:<digest>`, класс `UNLISTED`. Хеши имён служат только
для сопоставления одинаковых *неизвестных ключей*, не идентифицируют прокси.
При необходимости расшифровывать имена неизвестных полей следует **локально**
и отдельно подтверждать допустимость их публикации.

Ограничение: матрица перечисляет имена из source URI и некоторые внутренние
алиасы. Статистика показывает имена в `config.params`, то есть **после
ingest**. Поля из authority / fragment, преобразованные ingest в
`server`, `port`, `name`, не учитываются как `config.params`.
Поэтому `UNLISTED` не обязательно означает неправильный URI, а
известный `SPEC` не доказывает, что его значение допустимо или
что mapper поддерживает соответствующий JSON.

Аудит не запускает sing-box, не выполняет сетевые запросы и ничего не
записывает в `data/work`. Следующий этап — совместить частоты с
`M/C/GAP/META` и отдельно проверенной совместимостью target backend.
Не использовать отчёт как основание для silent drop в production.

## Этап 2: статистика контекстов и структуры значений без раскрытия секретов

После аудита `03-safe.jsonl` (8 848 записей) и идентификации поля
`cs` (45 VLESS + 126 VMess + 2 Trojan) добавлен read-only инструмент
`tools/audit_uri_semantics.py`. Он **не меняет** ни ingest, ни mapper,
ни `data/work` и не проверяет сетевую совместимость.

Запуск из каталога `app/` на ноутбуке:

```bash
python3 -m unittest tests.test_audit_uri_provenance tests.test_audit_uri_semantics -v

python3 tools/audit_uri_semantics.py \
  --checkpoint ../data/work/03-safe.jsonl \
  --output /tmp/proxyfilter-uri-semantic-audit.json
```

Отчёт содержит раздельно по протоколам:

- количество `UNLISTED` (только число, без имён и хешей);
- частоты **только ограниченного набора общеизвестных** значений
  `type`, `net`, `headerType`, `security`, `tls`, `mode`;
  любое другое значение заменяется на `<other>`;
- распределение `headerType` по выбранному транспорту;
- `cs`/алиасы: пустое, неверный тип, невалидный формат, дублирующиеся
  cipher suite имена, либо **число элементов** списка без их имён,
  плюс контекст TLS/транспорта;
- XHTTP `extra`: JSON-text vs Base64URL(JSON), недопустимое/слишком большое
  значение, top-level JSON тип (object/array/scalar/null) и контекст
  транспорта/TLS, **без вывода вложенных имён и значений**.

Особенности интерпретации:

1. В VMess `type` — header/disguise, а транспорт выбирает **`net`**.
2. Для остальных протоколов контекст транспорта определяется по `type`,
   при его отсутствии пробуется `net`; это агрегирование **именования**,
   не доказательство правильности URI.
3. `cs` не является VMess `scy`: выбор TLS cipher suites и шифр
   VMess раздельны. Список `cs` из аудита нельзя считать допустимым
   для TLS лишь потому, что он синтаксически похож на список.
4. Определение кодирования `extra` выполняется как read-only анализ
   формы. Оно **не** преобразует параметр и не выбирает автоматически
   способ декодирования для production.
5. Статистика `03-safe` не содержит отвергнутые до этой стадии URI;
   результаты подвержены selection bias. Для полной картины необходим
   отдельный запуск на `01-parsed` с тем же кодом.
6. Поля UNKNOWN/UNLISTED не распознаются по значениям и не выводятся
   как raw key. Известные строки вне фиксированного словаря также
   обобщаются в `<other>`; пароли, UUID, адреса, URI, paths и XHTTP
   nested properties не записываются.

Цель этапа — получить **измеряемую картину семантических контекстов** перед
выбором валидаторов. Следующий шаг после локального отчёта: определить
какие комбинации достоверны, какие требуют fixture, и какие необходимо
явно отклонять при экспериментальном URI → native JSON mapping.

## Результаты реальных проверок provenance v4 и semantic v1

Источник: локальные агрегированные отчёты `03-safe.jsonl`,
8 848 корректных строк и 0 ошибок. Это анализ наблюдаемого набора,
**не оценка процентной совместимости native mapper**.

**Provenance v4 после обновления матрицы:**

| Семейство | UNLISTED вхождений |
|---|---:|
| VLESS | 19 |
| VMess | 11 |
| Trojan | 5 |
| SS | 5 |
| Hysteria2 | 0 |
| **Всего** | **40** |

В отдельном semantic v1 остались устаревшие счётчики `UNLISTED`
(VLESS 46, VMess 19, всего 75): отчёт получен до обновления
поимённого реестра. Эти показатели нельзя сопоставлять как
разные результаты одного и того же состояния кода.

**Семантические наблюдения:**

- VMess `cs`: **126/126 пустых строк**, несмотря на присутствие
  104 записей с `tls=tls`, 3 с `tls=none` и 19 с пустым `tls`.
  Для них `cs` не задаёт содержательного списка cipher suites.
  Нельзя автоматически заполнять `tls.cipher_suites` пустым списком,
  пока не подтверждена семантика empty vs absent в целевом ядре.
- VLESS `cs`: 45 записей, все `security=tls`, все `type=ws`;
  29 содержат один suite identifier, 16 — пять или более.
  Аудит сознательно не раскрывает сами cipher suite names, поэтому
  **корректность suites не установлена**.
- VLESS `extra`: **249** значений, из них **246 JSON-text**, **3
  не распознаны**, **241 top-level object**, **5 JSON null**.
  XHTTP встречается в 248 из 249 записей; точную совместимость
  вложенных ключей с backend нельзя установить по top-level форме.
- Trojan `extra`: одно JSON-text object при `type=xhttp`.
- VLESS `headerType`: 1 547 `none`, 40 пустых, 19 `http`,
  12 с нераспознанным безопасным словарём значением. Из 1 618
  вхождений 1 537 встречаются с `type=tcp`, 69 с `type=ws`,
  12 с `type=xhttp`. Нужна **совместная таблица значений
  и транспорта**: отдельно перечисленные распределения её не заменяют.
- Trojan `headerType`: 399 `none`, 7 пустых, 1 `http`,
  1 `<other>`; 407 при TCP и 1 при RAW.
- VLESS `mode`: 804 вхождения, 280 `<other>`.
  `<other>` — намеренная приватная агрегация, **не**
  подтверждение невалидности. Для решения о mapping нужен локальный
  анализ конкретных значений с контролируемым раскрытием.
- VMess `type`: 31 `null`, 67 пустых, 86 `<other>`,
  336 `none`, 17 `http`, 1 `ws`.
  **VMess `type` — не transport selector**, транспорт — `net`.
- Trojan `cs`: 2 записи с 5+ cipher suite identifiers, однако
  `security` явно отсутствует. Отсутствие параметра security в URI
  само по себе не позволяет делать вывод, выключен ли TLS:
  для Trojan TLS может следовать из протокола по умолчанию.

**Исправления инструмента после анализа:** начиная с
`uri-semantic-aggregation-v2`, убран вводящий в заблуждение счётчик
`cs.tls_marker` (наличие `cs` делало его всегда true), вместо него
добавлена `cs.tls_activation` — **наблюдаемое значение selector**, не
фактическое состояние TLS. Добавлены безопасные перекрёстные таблицы
`headerType_value_by_transport` и `extra.encoding_by_transport`.
Имена неизвестных значений по-прежнему не публикуются.

**Следующий gate:** повторить semantic v2 после обновления матрицы и
исследовать расхождения `headerType` при WS/XHTTP, `extra=null`,
три нераспознанных `extra`, `mode=<other>`; затем сформировать
проверяемые fixtures для native mapping. В production никаких
изменений не требуется.

## Семантический аудит v2: перекрёстная проверка транспорта

Локальный отчёт `uri-semantic-aggregation-v2` по `03-safe.jsonl`:
8 848 валидных записей, 0 ошибок; UNLISTED:
VLESS 19, VMess 11, Trojan 5, SS 5, Hysteria2 0 (**40 всего**).
Все подсчёты в разделе ниже основаны на агрегированном отчёте;
полные исходные URI/значения не представлены.

### Header type × transport

| Протокол | Транспорт | `headerType` bucket | Записей |
|---|---|---|---:|
| VLESS | tcp | none / empty / http / other | 1487 / 23 / 19 / 8 |
| VLESS | ws | none / empty | 52 / 17 |
| VLESS | xhttp | none / other | 8 / 4 |
| Trojan | tcp | none / empty / http / other | 398 / 7 / 1 / 1 |
| Trojan | raw | none | 1 |
| SS | tcp | none | 7 |

`other` не равно ошибке: значение просто не входит в приватный
ограниченный словарь отчёта. Для TCP `http` — **20** записей,
требующих явного решения по HTTP-disguise. В текущем
`singbox_backend.py` TCP `headerType` кроме `""`/`none`
**отклоняется**, то есть его нельзя молча отобразить как обычный TCP.

### XHTTP `extra` по кодированию и транспорту

VLESS: 249 вхождений:
- xhttp + JSON-text object/null: 246;
- xhttp + invalid: 2;
- транспорт отсутствует + invalid: 1.

Из 246 JSON-text значений 241 имеет top-level object, 5 — JSON null.
Trojan: 1 XHTTP + JSON-text object.
Ни одного распознанного Base64URL(JSON) в этом checkpoint.

**Обнаруженное расхождение реализаций:** экспериментальный
`native_experiment.py` в ветке сейчас проверяет `extra` как
Base64URL(JSON) при XHTTP, тогда как `singbox_backend.py`
поддерживает JSON-text. Следовательно, на данной выборке 246 VLESS
и 1 Trojan XHTTP с распознанным JSON-text не пройдут **именно
экспериментальный Base64URL-only gate**, даже если часть имеет
допустимую вложенную схему. Это не доказательство, что production URI
parser принимает JSON-text эквивалентно: перед изменением gate
проверить parser oracle на конкретных URI и не изменять ingest.

Вложенная структура XHTTP (`xmux`, `downloadSettings` и прочие
поля) в отчёте v2 **не раскрывается и не проверяется**.
Значения JSON null и invalid нельзя превращать в пустой объект.

### TLS cipher suites

- VLESS: `cs` в 45 WS+TLS записях: 29 со структурой списка из 1
  шифросюита, 16 с 5+.
- VMess: **126/126** `cs=""`; TLS selector: 104 `tls`,
  3 `none`, 19 empty.
- Trojan: 2 списка из 5+ элементов при отсутствии explicit
  `security`; default Trojan TLS нельзя выводить из одного selector.

**Проблема существующего backend:** `_colon_list_value_exact("")`
даёт `[""]`, а не пустой список. Следовательно, текущий путь
`cs=""` может сериализовать TLS `cipher_suites: [""]`.
Это требует отдельного теста семантической эквивалентности и
fail-closed решения; не вводить автоматическое исправление на
основании только статистики.

### Остаточные семантические пробелы

- VLESS `mode=<other>`: **280** вхождений из 804 — для анализа
  значений нужен ограниченный локальный audit, текущий JSON
  принципиально не содержит значения.
- VMess `type=<other>`: **86** вхождений из 538; `type` — TCP
  header/disguise, не alias `net` (transport).
- Три invalid `extra` и пять JSON null требуют source-specific
  fixtures. Текущий отчёт не доказывает порчу URI: необходимо
  увидеть форму исходного `original_raw` локально.
- Отсутствие TUIC в 8 848 записей означает отсутствие эмпирической
  проверки этой семьи, а не её полную поддержку.

**Порядок следующих задач:** (1) validate experimental `extra`
gate против реального sing-box-extended URI parser;
(2) отдельный тест на `cs=""`, без изменения значений;
(3) read-only исследование `mode=<other>` и
`headerType=<other>`; (4) fixtures для спорных случаев.
Production ingest и identity не менять.

## Исходный код URI-парсера целевого sing-box-extended: верификация gate

Сверено по ветке `extended` репозитория
[dioxine/sing-box-extended](https://github.com/dioxine/sing-box-extended/tree/extended/parser/link)
(не является утверждением об иных форках или версиях):

- [VLESS parser](https://github.com/dioxine/sing-box-extended/blob/extended/parser/link/vless.go):
  для `type=xhttp` выполняется
  `common.DecodeBase64URLSafe(extra)`, затем `json.Unmarshal`.
  Если декодирование или JSON-разбор не удаётся, значения из
  `extra` **не применяются**. Это подтверждает, почему
  JSON-text в 246 наблюдаемых ссылках не даёт тех же XHTTP настроек
  в целевом URI-парсере, что JSON-text → native JSON.
  Эксперимент продолжает *явно отклонять* JSON-text, а не
  молча восстанавливать или игнорировать настройки.
- [VMess parser](https://github.com/dioxine/sing-box-extended/blob/extended/parser/link/vmess.go),
  [Trojan parser](https://github.com/dioxine/sing-box-extended/blob/extended/parser/link/trojan.go)
  и VLESS parser: в проверенном коде отсутствует ветка,
  применяющая параметр `cs` к TLS cipher suites. Непустое
  `cs` → `cipher_suites` в native JSON может поэтому
  изменить TLS handshake по сравнению с target URI parser.
  Экспериментальный native mapper отклоняет как пустой
  (`empty_tls_cipher_suites`), так и непустой
  (`unsupported_tls_cipher_suites`) `cs` и его явные
  алиасы, вместо небезопасного маппинга.

Статистика 126 VMess с пустым `cs`, 45 VLESS с непустым `cs`
и 2 Trojan с непустым `cs` — **наблюдения**, а не доказательство
одинакового поведения вне указанного форка. Production backend,
ingest, dedup и хранение не менялись.

Возможный следующий эксперимент: локальное сравнение URI parser oracle
и native JSON для синтетических XHTTP `extra` с известным набором
полей (`xPaddingBytes`, `xmux`), в том числе JSON-text,
Base64URL(JSON), invalid, JSON null. Не переносить поведение
чужого форка автоматически на `dioxine/sing-box-extended`.

## Сравнительный аудит реализаций: Nekoray / Throne / NekoBox

Дополнительные источники (изучение кода, **не** нормативный URI
контракт) для XHTTP:

1. **Nekoray** [MatsuriDayo/nekoray](https://github.com/MatsuriDayo/nekoray)
   архивирован в марте 2025 года: пригоден как исторический baseline,
   но не отражает современные XHTTP extension exports.
2. **Throne** [throneproj/Throne](https://github.com/throneproj/Throne),
   активный наследник Nekoray. В
   [`src/configs/common/xrayStreamSetting.cpp`](https://github.com/throneproj/Throne/blob/dev/src/configs/common/xrayStreamSetting.cpp)
   `xrayXHTTP::ParseFromLink` извлекает `extra` из query и
   вызывает `ParseExtraJson`; JSON-object параметры разбираются в
   `parseXHTTPExtraObject`. Также распознаётся прямой
   `x_padding_bytes`. `ParseExtraJson` имеет **эвристику**
   преобразования Python dict repr (`'...'`, `True`, `False`)
   после неудачи строгого JSON. Эта эвристика **неприемлема**
   для консервативного `proxy-filter`: переписывание входа
   без доказанной эквивалентности запрещено.
   Неизвестные вложенные ключи сохраняются Throne в `rawExtra`,
   что подтверждает важность unrecognized-field accounting.
3. **Throne** поддерживает раздельную структуру Xray-профилей и
   XHTTP, а не обязуется эквивалентно преобразовывать их в
   native sing-box JSON. Поэтому его успешный импорт не означает
   переносимости всех опций `downloadSettings`, `xmux`,
   `xPaddingBytes` в целевой backend.
4. **NekoBox Android / Throne Android** должны рассматриваться как
   самостоятельные парсеры и конвертеры; подтверждённых строк кода
   для XHTTP `extra` в этом сравнении пока нет. Не делать
   выводов об их поведении по названию проекта.

**Подтверждённое различие:** целевой
[dioxine/sing-box-extended VLESS parser](https://github.com/dioxine/sing-box-extended/blob/extended/parser/link/vless.go)
ожидает Base64URL(JSON), а Throne `xrayXHTTP::ParseFromLink`
принимает JSON-text. Оба поведения встречаются в живых
экосистемах, но не могут быть автоматически объединены в
консервативном mapper. Для `proxy-filter` сохраняем исходное
значение и отклоняем неподтверждённое эквивалентное преобразование.

## Сторонние парсеры: источники решений, не режимы proxy-filter

Проверенные источники: [Podkop](https://github.com/itdoginfo/podkop),
[NetShift](https://github.com/xDarkOne/netshift),
[Forkop](https://github.com/ushan0v/forkop),
[podkop-engine: таблица URI → outbound](https://github.com/podkop-net/podkop-engine/blob/main/docs/LINKS.md),
а также Throne и исходный URI-парсер целевого `dioxine/sing-box-extended`.

Реализации отличаются в важных местах: например, XHTTP `extra` у
podkop-engine принимает URL-экранированный JSON, а у проверенного
парсера sing-box-extended — Base64URL(JSON). Их механическое объединение
или автоматическое определение «подходящего» формата меняет семантику
URI и нарушает принятый консервативный контракт.

**Архитектурное решение (2026-11-05):** в проекте остаётся один
экспериментальный `convert_uri_to_native(proxy)` с поведением,
ориентированным на целевое sing-box-extended. Отдельный профиль
`podkop-engine`, CLI differential harness и внешний oracle удалены
как не нужные production-задаче. Никакой внешний бинарник Podkop
для работы или тестирования проекта не требуется.

Правила сторонних проектов можно переносить в единый адаптер лишь
после проверки, что они сохраняют смысл исходного URI и поддерживаются
целевым sing-box. Они не служат основанием для исправления повреждённых
URI, добавления структурированных входных форматов или потери
неизвестных параметров.

Сохранены существующие тесты `tests.test_native_experiment` на
TLS/REALITY, alias-конфликты, VMess, XHTTP и неизменность
`original_raw`. Эксперимент не подключён к production backend selector.

Проверка из `app/` на ноутбуке:

```bash
python3 -m unittest tests.test_native_experiment tests.test_audit_uri_provenance tests.test_audit_uri_semantics -v
```

## Аудит покрытия native-конвертера на реальном checkpoint

В `tools/audit_native_coverage.py` добавлен **read-only** проход по
`data/work/03-safe.jsonl` (по умолчанию). Он не вызывает sing-box,
не выполняет сетевых запросов, не меняет записи и не подключён к
production pipeline. Строки реконструируются только во временные
`ProxyConfig` и проверяются текущим `convert_uri_to_native(proxy)`.

Основные показатели:
- `native_ok_no_unclassified_loss` — native JSON сформирован без
  сбрасывания нераспознанных полей (только кандидат на дальнейшую
  проверку, а не доказательство эквивалентности);
- `native_ok_unclassified_loss` — JSON сформирован, но неизвестные
  исходные поля отброшены: **не безопасно для автоматического
  переключения**;
- `rejected` и `reasons` — отказ и агрегированная причина
  из фиксированного набора кодов; `backend_rejected` без утечки
  произвольного текста ошибки;
- `invalid_rows` и `skipped_non_uri` — отдельно от URI-покрытия.

Запуск из `app/` на ноутбуке:

```bash
python3 -m unittest tests.test_audit_native_coverage -v
python3 tools/audit_native_coverage.py \
  --checkpoint ../data/work/03-safe.jsonl \
  --output /tmp/proxyfilter-native-coverage.json
```

Инструмент выводит агрегаты по протоколам и причинам отказов;
в отчёте **нет** ссылок URI, хостов, UUID, паролей, сырых
параметров и непроверенных имён полей. `hy2` агрегируется
в `hysteria2`.

Аудит измеряет лишь способность **сформировать структуру JSON**
и характер потерь. Действительная принимаемость выходного JSON
целевым sing-box, идентичность семантики и сетевая
работоспособность этим аудитом **не проверяются**.

## Сопоставление предыдущих аудитов с native coverage (2026-11-05)

**Основания:** уже зафиксированные в этом документе provenance v4,
semantic v2 по `03-safe.jsonl` (8 848 URI), плюс локальный отчёт
`native-uri-coverage-v1` пользователя по тем же 8 848 записям.
Данных о пересечениях конкретных записей между агрегированными отчётами нет.

Native coverage: `6351` успешных без *неизвестных* потерь,
`44` успешных со сброшенными неизвестными полями,
`2453` отказа. Успех не равен `sing-box check` или
эквивалентности исходному URI.

| Native reason | Число | Предыдущее подтверждённое наблюдение | Решение |
|---|---:|---|---|
| `unsupported_connection_field` | 1136 | Матрица содержит отдельные известных connection-sensitive поля и их происхождение, но ни provenance v4, ни semantic v2 не связывает каждую запись с **первым отказом** native | Не объявлять одно поле виновником 1136; нужны точные пересечения только если это потребуется для исправления |
| `transport_fields_on_tcp` | 412 | semantic v2: у VLESS 1537 `headerType` при TCP (в основном `none`); при TCP есть 20 `http` VLESS/Trojan | Не считать все 412 ошибочными или нейтральными; нельзя преобразовывать HTTP disguise в обычный TCP |
| `reality_missing_fingerprint` | 306 | В отчётах нет доказательства наличия/потери `fp` для именно этих 306 записей | Не изобретать fingerprint; проверить ingest только при наличии конкретного воспроизводимого случая |
| `invalid_xhttp_extra_encoding` | 148; `invalid_xhttp_extra_json` 5 | semantic v2: 246 VLESS XHTTP `extra` — JSON-text, пять `null`, два invalid XHTTP; ни одного распознанного Base64URL(JSON) | JSON-text в native не считать эквивалентным URI-парсеру extended; строгий gate сохранить. 148 — число первых отказов, не число всех JSON-text |
| `empty_tls_cipher_suites` | 126 | semantic v2: все 126 VMess `cs` — пустые строки; исходный extended parser не применяет `cs` как TLS cipher suites | Не генерировать `cipher_suites: [""]`; вопрос о доказанно нейтральном пропуске `cs` оставить открытым до точной проверки |
| `unsupported_vmess_header` | 74 | semantic v2: VMess `type` — заголовок, не `net`; 17 `http`, 1 `ws`, 86 `other` во всей базе | Не переписывать `type` в transport и не считать все нестандартные значения невалидными |
| `unsupported_vless_encryption` | 75 | Нормативная матрица содержит `encryption` как connection-sensitive свойство | Не менять/удалять значение ради увеличения покрытия |
| `unmapped_connection_field` | 97 | Встречающиеся имена описаны в provenance, но связь с первым отказом не восстановима по агрегатам | Оставить консервативный отказ |
| Прочие первые отказы | 74 | Причины менее частотны и неоднородны | Разбирать после доказанных случаев |

**Суммарные 2453 отказа — только первые причины.**
Статистика предыдущих аудитов описывает наличие и контексты полей,
а не контрфактическое число успешных конверсий после исправления.

**Инженерное решение:** на этом этапе не менять native gate ради
увеличения процента. Ранее собранные данные достаточно объясняют
группы `cs`, XHTTP и VMess, но не удостоверяют новые
безопасные преобразования. Следующее предметное изменение —
узкий тест конкретного URI-семантического случая на целевом
sing-box-extended и только затем код адаптера. Не повторять
общий provenance/semantic сбор и не менять production.

## Подтверждённое точечное исключение: VMess `cs=""`

Проверен исходный код целевого
[`dioxine/sing-box-extended/parser/link/vmess.go`](https://github.com/dioxine/sing-box-extended/blob/extended/parser/link/vmess.go),
ветка `extended`, Git blob
`d3a09711efedaab6f567ae71765109f23614e391`.
В `parseVMessLink` отсутствует обработчик ключа `cs`, в том числе
пустого: `cs=""` не влияет на URI-parsed TLS options.

В изолированном `convert_uri_to_native` при VMess **только**
`cs=""` удаляется из временной копии перед JSON mapping. Иначе
общий backend сформировал бы `tls.cipher_suites=[""]`, чего
целевой URI parser не делает. `original_raw` и `params`
остаются verbatim. Никаких пустых cipher suites не создаётся.

Это **не** разрешение автоматически удалять другие URI-параметры,
пустые `cipher_suites`/`cipher-suites` или менять VLESS/Trojan;
`cs` с непустым значением пока отклоняется консервативно.
Успешная генерация JSON не равна `sing-box check` и не подтверждает
эквивалентность установленного бинарника. Этот вывод относится
к проверенному исходному дереву, не ко всем версиям форка.

Повторный аудит после локальных тестов:
```bash
python3 -m unittest tests.test_native_experiment tests.test_audit_native_coverage -v
python3 tools/audit_native_coverage.py \
  --checkpoint ../data/work/03-safe.jsonl \
  --output /tmp/proxyfilter-native-coverage-after-vmess-cs.json
```
Не обещать автоматически +126 к `native_ok_no_unclassified_loss`:
после прохождения первого gate запись может получить другой отказ.

## Точечный VMess TCP HTTP disguise mapping (2026-11-05)

**Контракт:** legacy VMess Base64(JSON) использует `net` как
transport selector, `type` — как header/disguise selector.
См. выше «Семантический контракт полей», пункты VMess `net`
и `type`. Проверены независимо:

- [2dust/v2rayN, Description of VMess share link](https://github.com/2dust/v2rayN/wiki/Description-of-VMess-share-link):
  `type=http` для TCP, `host`/`path` зависят от типа транспорта;
- [dioxine/sing-box-extended parser/link/vmess.go](https://github.com/dioxine/sing-box-extended/blob/extended/parser/link/vmess.go),
  проверенный Git blob `d3a09711efedaab6f567ae71765109f23614e391`:
  только `net=tcp` и `type=http` создают
  `V2RayTransportTypeHTTP`, значения `method`, `path`, `host`
  перенесены в `HTTPOptions`. Сам `type` не является `net`.

В **экспериментальном** `convert_uri_to_native` для явного
`net=tcp&type=http` создаётся native `transport.type=http`.
Проверенные простые поля `host` (один хост), `path`, `method`
переходят в `transport.host` (одноэлементный массив),
`transport.path`, `transport.method`.
`original_raw` и `params` не меняются.

**Границы:**

- Стандартные схемы Xray/v2rayN допускают список HTTP hosts,
  разделённый запятыми, но исходный код целевого `extended`
  формирует `Host = []string{host}` без разделения.
  Поэтому VMess TCP HTTP с запятой в `host` пока **отклоняется**,
  вместо выбора несовместимых семантик.
- `headers` пока отклоняется: для него нет подтверждённого
  безопасного преобразования строкового JSON-поля VMess в native
  `HTTPHeader`.
- `type=http` вне явного `net=tcp`, нестандартные header types,
  `method` вне TCP HTTP, `serviceName` в TCP, некорректные типы
  значений не преобразуются по догадке.
- Наличие native HTTP transport ещё не доказывает `sing-box check`
  или совместимость с удалённым сервером. Проверка на реальном
  бинарнике и переаудит необходимы перед любым production-переносом.

Команды на ноутбуке, из `app/`:

```bash
python3 -m unittest tests.test_native_experiment tests.test_audit_native_coverage -v
python3 tools/audit_native_coverage.py \
  --checkpoint ../data/work/03-safe.jsonl \
  --output /tmp/proxyfilter-native-coverage-after-vmess-http.json
jq '.protocols.vmess' /tmp/proxyfilter-native-coverage-after-vmess-http.json
```

## Сравнительный аудит готовых URI-реализаций (2026-11-05)

**Назначение:** искать проверенную семантику URI-полей и архитектурные решения
*до* расширения собственного конвертера. Этот раздел не меняет
классификацию происхождения в таблицах выше автоматически и не
санкционирует копирование чужих допущений. Граница PF: TXT/Base64(TXT)
→ семь URI-схем (шесть семейств); Xray JSON, Clash YAML и sing-box JSON
не становятся production input.

### Источники, уровень доказательности и применимость

| Источник | Проверенный артефакт | Что подтверждает | Что **не** подтверждает |
|---|---|---|---|
| **Podkop** (P) | [podkop-engine docs/LINKS.md](https://github.com/podkop-net/podkop-engine/blob/main/docs/LINKS.md), blob `34a62f58f49a3ec5ddadde89f30ec7f1980645c4` | Поведение `tools decode-link`, документированные URI→outbound mappings, предупреждения и отказы; авторы сообщают о запуске каждой табличной строки на **r15**, full 1.13.21 и 1.14.3 | Эквивалентность с **нашим** зафиксированным sing-box-extended, принятие всех расширений/дефолтов и сохранение неизвестных полей |
| **Sing-Box Launcher** (L) | [контракт VMess](https://github.com/Leadaxe/singbox-launcher/blob/main/contract/registry/protocols/vmess.json), [VLESS](https://github.com/Leadaxe/singbox-launcher/blob/main/contract/registry/protocols/vless.json), [HY2](https://github.com/Leadaxe/singbox-launcher/blob/main/contract/registry/protocols/hysteria2.json), [TUIC](https://github.com/Leadaxe/singbox-launcher/blob/main/contract/registry/protocols/tuic.json); [DRIFT](https://github.com/Leadaxe/singbox-launcher/blob/main/SPECS/131-F-O-UNIFIED_NODE_PIPELINE/DRIFT.md); blobs VMess `6f5e6168dd47bb41dd898d0bd7201b9e09392b53`, VLESS `132567c30374d4ef4de4751d44920667208d4494`, HY2 `7ef420689999bead451de9784ccf4352d07ae5ac`, TUIC `6c6c8a48077760a9cb6bf8c63a741fc9dbb7089c` | Поля, типы, aliases, контекст, потенциальные defaults; идея контрактного реестра и раздельных parser/model/emitter. DRIFT фиксирует реальные несогласованности Go/Dart | Соответствие двух версий самого Launcher; корректность дефолтов/алиасов для PF или другого ядра. Часть текстов реестра описывает исторический код, не только текущую реализацию |
| **Link Parser To JSON** (J) | [README](https://github.com/iroblivionspark/link-parser/blob/main/README.md), blob `0dd1c6bc38fa285d20113b2023c835f83d9aa371` | Заявлены VMess/VLESS/Trojan/SS/HY2/TUIC, выходы Xray/V2Ray и sing-box **1.14.1**, разделение «outbound / полный config» и явное отклонение неподдерживаемого REALITY/XHTTP в V2Ray target | Семантика **конкретных** URI-полей, отсутствие потерь и фактическая корректность сгенерированного JSON — код/тесты для этих утверждений **не проверены** |
| **Целевой EXT** (E) | [sing-box-extended parser/link/vmess.go](https://github.com/dioxine/sing-box-extended/blob/extended/parser/link/vmess.go), проверенный blob `d3a09711efedaab6f567ae71765109f23614e391` и раздел выше «Исходный код URI-парсера» | Поведение **проверенной** ветки для сравнения, в частности VMess `net=tcp&type=http` и `cs` | Корректность по Xray/v2rayN, другим форкам и всем бинарникам/версиям |

**Статус источников:** P — табличные результаты внешних прогонов;
L — прочитанные реестры и опубликованный внутренний DRIFT-анализ;
J — только описание возможностей; E — исходный код.
Источник другой реализации = `EXT` либо `LEGACY` **только при
подтверждении точного URI-формата**; не превращать произвольные
имена в `SPEC` по одному факту их наличия в реестре.

### Варианты URI и политика парсинга: существенные расхождения

| Вопрос | Подтверждённое внешнее поведение | Решение для PF |
|---|---|---|
| Scope форматов | P разбирает также HTTP/SOCKS/AnyTLS и **VMess URL-форму**; VMess доступен только в `podkop-engine-full`. L включает дополнительные семейства, форматы Xray/sing-box и контейнеры. J генерирует несколько видов полного JSON-конфига | Не расширять production input сверх принятого списка и VMess Base64(JSON) |
| Регистр и HTML-артефакты | P сравнивает query keys без учёта регистра и снимает префикс `amp;` | Не принимать `amp;` за доказанный эквивалент исходного URI; регистр имён — отдельно по спецификации и ingest |
| Повторные query keys | P берёт **первое** значение | Наш строгий reject дублей оставить; first-wins теряет данные |
| Неизвестные и контекстно неуместные поля | P предупреждает и игнорирует неизвестное поле, чужие transport/TLS поля нередко игнорирует **без предупреждения** | Не считать такой исход `no_unclassified_loss`; не копировать «best effort» |
| Исправления и fallback | P убирает BOM/краевые пробелы, допускает дополнительные варианты URI; L normalizes `scy`, uTLS, часть security и отдельно предупреждает о деградации | Не исправлять неверное encoding/URI и не подменять значения без доказанной эквивалентности |
| Обработка секретов | P отделяет stderr и stdout, подавляет URI в сообщениях; выводит outbound только после конструирования ядром | Использовать **идею** безопасных структурированных причин отказа; никогда не писать URI/пароли в аудит |
| Проверка результата | P сообщает, что stdout появляется после конструирования outbound самим sing-box, а не просто JSON-serialize | Разделять `parsed`, `mapped`, `sing-box check`, реальный network test. Собранный JSON не гарантирует handshake |
| Арбитраж явных настроек | P имеет расширение `sb.<path>`, которое может **перекрывать** другое поле URI, в том числе `sni` | Отмечать как **vendor extension**, не превращать в универсальный fallback и не выбирать победителя автоматически |
| Контрактный реестр | L хранит protocol JSON с `type`, `aliases`, `default`, `maps_to`, `impl` и корпусом fixtures; DRIFT показывает несовпадение Go/Dart | Заимствовать **метод**: единый field registry + матрица условий + golden fixtures; не менять действующий ingest до решения архитектуры |

### Поля и зависимости: пополнение матрицы

Ниже «внешнее наблюдение» не является разрешением на преобразование.
Ссылки P/L/E определены в таблице источников выше.

| URI-family / поле | Внешнее наблюдение | Путь JSON / контекст | Статус и решение PF |
|---|---|---|---|
| **VMess** `net` / `type` | P: в Base64(JSON) `net` определяет transport, `type` определяет TCP-header, при gRPC — mode; L отдельно перечисляет оба, E для `net=tcp&type=http` создаёт HTTP transport | `transport.type` только при соответствующем контексте | `LEGACY`, C; нельзя считать `type` общим с VLESS selector |
| VMess `net=tcp&type=http`, `host`, `path`, `method` | P: HTTP disguise, `host` — CSV, `path` — путь; E использует **один** `host` как одну строку в массиве и также переносит `method` | `transport.type=http`, `transport.host[]`, `path`, `method` | C **с расхождением** CSV semantics. У PF уже есть экспериментальная поддержка узкого случая, проверить отдельно TLS и заголовки |
| **Критический конфликт VMess TCP HTTP + TLS** | P явно **отказывает** HTTP-disguise с TLS/REALITY: его native HTTP transport при TLS говорит HTTP/2, а Xray TCP HTTP disguise — HTTP/1.1. E создаёт HTTP transport и при TLS без аналогичного gate | `tls.enabled` × `transport.type=http` | **GAP / потенциальная неверная семантика существующего native mapping.** Перед расширением покрытия поставить независимый oracle A/B, временно не объявлять эти записи эквивалентными. Сведения P и E нельзя слить в одну «истину» |
| VMess `net=grpc&type=multi`, `path` | P: `path` = имя сервиса, `multi` заменяется на gun с предупреждением; `type` не transport selector | `transport.service_name` / gRPC mode | C/GAP: не переносить деградацию mode без согласия сервера |
| VMess `net=ws&path=/ws?ed=N` | P: `ed` извлекается из path, `early_data_header_name` = `Sec-WebSocket-Protocol`; L также исследует `splitWSEarlyData` | `transport.max_early_data`, `early_data_header_name`, остаточный `path` | `LEGACY`, C; для URI Base64(JSON) требуется тест разделителя/повторного percent decoding |
| VMess `scy` | P принимает ограниченные значения и для прочих применяет `auto` с warning; L DRIFT фиксирует случаи, когда неизвестный cipher заменяется на `auto` | `security` | `LEGACY`, C; **не заменять** неизвестный исходный шифр на auto. Коды совместимости ядра отличать от редакторских исправлений |
| **VLESS** `packetEncoding=none` | P: в VLESS explicit `none` отображается пустой строкой, чтобы отключить default XUDP; `packet` → `packetaddr` | `packet_encoding` | `EXT`, C; отсутствие поля не всегда равно явному `none`. Проверить на зафиксированном backend перед mapping |
| VLESS `flow=xtls-rprx-vision` × transport | P требует TLS/REALITY и обычный TCP, если нет отдельного VLESS encryption; L DRIFT отмечает нормализацию `flow` при transport | `flow`, `tls`, `transport`, `encryption` | C; не удалять `flow` автоматически; не переносить Xray-специфичные правила на другой backend |
| VLESS `encryption=mlkem768x25519plus…` | P r14 поддерживает новое VLESS Encryption и проводит отдельную валидацию | `encryption` | `EXT`, GAP для нашей текущей версии; прежний отказ ненулевого encryption сохранять, пока зафиксированная сборка не проверена |
| **VLESS / Trojan** `headerType=http` при TCP | P: HTTP/1.1 disguise допустим только **без** TLS/REALITY; при TLS HTTP transport имеет другую wire semantics | `transport.type=http` | C/GAP; **не** переводить TCP HTTP disguise в native HTTP при TLS без отдельного доказательства |
| WS `host` и TLS `sni` | P при отсутствии WS `host` может использовать TLS SNI как Host, для Xray reverse proxy; L реестры контекстны | `transport.headers.Host` и `tls.server_name` | C; не выводить WS Host из SNI автоматически только по аналогии |
| **XHTTP** `extra` | P: принимает URL-escaped JSON object, иногда декодирует %-encoding повторно; E требует Base64URL(JSON) и на ошибках фактически игнорирует extra | `transport` / вложенные опции | `EXT`, **GAP между источниками**, намеренный fail-closed; повторное декодирование не внедрять |
| XHTTP `mode`, `xmux` и диапазоны | P: `mode=auto/packet-up/stream-up/stream-one`; ряд `xPaddingBytes`, `sessionIDLength`, `scMaxEachPostBytes` и др. отображается отдельно; P документирует приоритет значения в extra или query | `transport.mode`, `x_padding_bytes`, `xmux.*` | `EXT`, C/GAP; собрать schema-aware table приоритетов для **конкретной версии**. Не переносить чужие defaults без теста |
| **SS** `plugin` | P: SIP003 `name;opts`; `simple-obfs` → `obfs-local`, остальные options сохраняются | `plugin`, `plugin_opts` | `SPEC` только для SIP002/SIP003 при сверке норматива; C для alias simple-obfs, различать token и подстроку пароля |
| SS `type`, `security`, `headerType` | P принимает `tcp/raw/none` как не меняющие transport, прочие значения отклоняет | нет native V2Ray transport | C/OBSERVED: не гасить поля только по примеру Podkop, проверить каждое в нашем URI корпусе |
| **HY2** userinfo `user:password` | P рассматривает всю часть до `@` как **один пароль**, не разделяя по двоеточию | `password` | `SPEC` по Hysteria2 URI при сверке первоисточника; проверить parser/encoding на точной строке |
| HY2 `mport` / port ranges | P: port hopping, список в authority имеет приоритет над `mport`; L registry допускает `mport` alias `ports` и multiport | `server_ports`, `server_port` | C; при наличии обеих форм не терять одну без доказанного приоритета |
| HY2 `obfs=salamander`, `obfs-password` | P: пароль нужен только при obfs; у линии 1.14 отдельно `gecko`; L реестр явно фиксирует параметры gecko | `obfs.type`, `obfs.password`, версия-зависимые размеры | C; проверить зависимость/версию. Нельзя при неизвестном obfs незаметно выключать маскировку |
| HY2 `fm` | P иногда раскладывает JSON finalmask в `obfs` / hopping / bandwidth; отказывает маскам, меняющим wire protocol | много полей | **GAP**; сам факт наличия такого mapping у P не доказывает эквивалентность. Наш reject оставить |
| HY2/TUIC `fingerprint`, `fp`, `pinSHA256` | L registry **сводит** `fingerprint` к uTLS `fp` для части протоколов, хотя в нашей матрице `fingerprint` может означать certificate pin | `tls.utls.fingerprint` **или** certificate pin | **Критический конфликт**: не заимствовать этот alias. Сертификатный pin и fingerprint ClientHello — разные свойства |
| **TUIC** `congestion_control`, `udp_relay_mode` | P: `cubic/new_reno/bbr` и `native/quic`; L фиксирует default `cubic` и `native`, но признаёт drift явного emit-default | одноимённые outbound fields | `EXT`, C; отсутствие ≠ явно заданное значение. Проверить enum и реальные defaults целевого ядра |
| TUIC `reduce_rtt` / `zero_rtt_handshake` | P и L связывают разные alias с `zero_rtt_handshake` | `zero_rtt_handshake` | `EXT`, C; boolean aliases сравнивать строго при конфликтах, не «первое непустое» |
| TUIC `udp_over_stream` × `udp_relay_mode` | P: одновременно заданные режимы могут приводить к отказу конструктора outbound | `udp_over_stream`, `udp_relay_mode` | C/GAP; зависимость двух полей, нужна версия-зависимая проверка |
| TUIC `alpn` | P: для TUIC sing-box не предлагает ALPN по умолчанию и предупреждает об отсутствии; требование зависит от сервера | `tls.alpn` | C; не вставлять `h3` автоматически |

### Вывод о переносимости и дорожная карта

**Результат аудита: не копируем готовый парсер целиком.** У него другой
контракт: лишние входные форматы, first-wins/ignore правила, автоматические
исправления, нормализация vendor defaults и версии ядра. Используем:
(1) **матрицы P** как список гипотез/fixtures и ошибок;
(2) **контракт L** как схему для структурированного field registry
(`uri_family`, `field`, `location`, `value_type`,
`applicability`, `aliases`, `default`, `maps_to`, `provenance`,
`backend_support`, `semantic_risk`);
(3) **таблицу несовместимостей** и warning-коды для отказов;
(4) **проверку через конструктор целевого ядра** и отдельный runtime test.

**Приоритеты перед новым кодом:**

1. **P0 — проверить/ограничить уже написанное VMess TCP HTTP mapping
   при `tls=tls/reality`.** P указывает на HTTP/1.1 ↔ HTTP/2
   несовместимость; E не ставит gate. Не объявлять A/B с E достаточным
   подтверждением сохранения wire semantics.
2. P1 — выделить из 201 VMess `unsupported_connection_field`
   безопасные закрытые имена по уже имеющимся аудитам; неизвестные
   имена не публиковать.
3. P1 — VMess `net=grpc` + `path` и `type` — проверить на конкретном
   parser + backend, без молчаливого `multi` → gun.
4. P1 — VLESS/Trojan TCP `headerType` (включая `http` и
   TLS-совместимость), SS transport extension.
5. P2 — XHTTP `extra` и nested fields: раздельные форматы P/E,
   приоритеты `extra`/query, отдельные fixtures для JSON null и
   invalid, без повторного URL decoding.
6. P2 — HY2/TUIC alias collisions, `fm`, fingerprints и version
   gates; HY2/TUIC в корпусе не равномерно представлены.

**Юридический статус:** P и L распространяются с GPL-3.0, J — MIT;
проверены файлы LICENSE соответствующих репозиториев.
Заимствуем сейчас **факты, критерии и идеи**, а не текст/код.
Лицензия самого PF и условия возможного копирования сюда не
устанавливались.

**Граница выполненного:** проверены названные документы и реестры;
не запускались сторонние бинарники/тестовые корпуса и не проводился
новый `sing-box check` на нашем checkpoint. У J нет достаточного
полевого подтверждения; именно поэтому он не используется для
нормативного mapping отдельных параметров.

## VMess TCP HTTP + TLS: защита сетевой семантики (2026-11-05)

Сравнение **трёх оснований**: нашей матрицы (раздел «Сравнительный
аудит готовых URI-реализаций»), проверенного
[`parser/link/vmess.go`](https://github.com/dioxine/sing-box-extended/blob/extended/parser/link/vmess.go)
(`d3a09711efedaab6f567ae71765109f23614e391`),
и [Podkop `docs/LINKS.md`](https://github.com/podkop-net/podkop-engine/blob/main/docs/LINKS.md)
(таблицы VMess и транспорта; зафиксированный blob
`34a62f58f49a3ec5ddadde89f30ec7f1980645c4`).

- EXT при `net=tcp&type=http` создаёт
  `V2RayTransportTypeHTTP`, даже если `tls=tls`: это
  **описание поведения parser**, а не доказательство сетевой
  эквивалентности исходной TCP HTTP/1.1-маскировке.
- Podkop заявляет проверенное ограничение: HTTP TCP disguise
  совместим с native HTTP transport только **без TLS**.
  С TLS sing-box HTTP transport может перейти на HTTP/2,
  тогда как disguise перед исходным потоком использует HTTP/1.1.
- Следовательно, экспериментальный `convert_uri_to_native`
  теперь явно отклоняет `net=tcp&type=http` с активным либо
  неподтверждённо выключенным `tls`;
  причина `vmess_http_disguise_tls_conflict` (без значения поля
  и секрета в отчёте).
- Допустимы только отсутствие `tls` или точно подтверждённые
  отключающие строковые маркеры `""`, `none`, `0`,
  `false`. Любая нестроковая форма и остальные значения
  **отклоняются**, без переинтерпретации в native TLS.
  Правило не влияет на VMess WS/TLS и на прочие протоколы.
- Остаются действующими прежние границы: неоднозначный `host`
  со списком, `headers`, нетипизированные поля и другие TCP
  disguises не обрабатываются по догадке.

**Статус:** семантический fail-closed gate, не runtime-прогон.
Это может уменьшить число успешных native-преобразований, и такое
уменьшение **не дефект аудита**, если иначе меняется протокол
на проводе. Текущая реализация остаётся экспериментальной;
production input и `type=parser` не меняются.

Из `app/`:

```bash
python3 -m unittest tests.test_native_experiment tests.test_audit_native_coverage -v
python3 tools/audit_native_coverage.py \
  --checkpoint ../data/work/03-safe.jsonl \
  --output /tmp/proxyfilter-native-coverage-after-vmess-http-tls-gate.json
jq '.protocols.vmess | {rows, native_ok_no_unclassified_loss, rejected, reasons}' \
  /tmp/proxyfilter-native-coverage-after-vmess-http-tls-gate.json
```

## VMess: декомпозиция `unsupported_connection_field` (2026-11-05)

По последнему локальному отчёту: **201 из 364 VMess отказов**
получили `unsupported_connection_field`, что составляет 55,2% отказов
VMess. Это **не одна ошибка конкретного поля**. Из исходного кода
`proxyfilter/native_experiment.py` установлено, что до проверок TLS,
header/transport и backend действует пересечение
`set(params) & _UNSUPPORTED`. При наличии хотя бы одного совпадения
возвращается один общий код. Поскольку проверка первая, отчёт не
показывает вторые/последующие причины отказа.

### Закрытый список имён: это не результаты подсчёта checkpoint

| Семейство | Зарегистрированные имена `_UNSUPPORTED` | Семантика / дальнейшая проверка |
|---|---|---|
| FinalMask | `fm`, `final_mask` | Xray/обфускация и UDP-поведение; Podkop умеет частичное извлечение, но оно может не сохранить исходный wire protocol. Никакого универсального удаления |
| Certificate pin | `pcs`, `pinnedPeerCertSha256`, `peer_certificate_sha256`, `pinSHA256`, `pin_sha256` | Не тождественно uTLS fingerprint; отдельно установить тип pin (публичный ключ/сертификат) |
| ECH | `ech`, `echConfigList` | TLS ECH; нужна конкретная версия backend и эквивалентная форма |
| REALITY spider | `spx`, `spider_x` | Не считать metadata; target/backend может не поддерживать |
| Multiplex | `smux` | Семантика мультиплексора и протокол на проводе; недостаточно `multiplex.enabled` |
| Socket | `fastopen` | Не считать нейтральной настройкой только из-за отсутствия сетевого протокола |
| Realm | `realm-opts` | Версионное QUIC/HY2 расширение; для VMess контекст пока не подтверждён |
| Other | `token` | Назначение зависит от реализации; не классифицировать как рекламу |

**Важно:** наличие имени в глобальном `_UNSUPPORTED` не доказывает,
что оно вообще встречается у VMess. Таблица выше — карта гипотез,
а не распределение 201 записей.

Для фактического разбора добавлен **read-only** анализатор
`tools/audit_vmess_blockers.py`: он проверяет **реальный первый
отказ** каждой VMess URI-записи и считает `by_field`,
`by_group` и `by_combination`. Агрегаты не содержат URI, endpoint,
credentials, значения query или произвольные имена полей.
Числа по именам **могут перекрываться**: запись с `fm` и `ech`
будет учтена в обеих колонках, но только однажды в `rows`.
Классификация по этим именам не подтверждает
преобразуемость содержимого.

Команды на ноутбуке из `app/`:

```bash
python3 -m unittest tests.test_audit_vmess_blockers -v
python3 tools/audit_vmess_blockers.py \
  --checkpoint ../data/work/03-safe.jsonl \
  --output /tmp/proxyfilter-vmess-blockers.json
cat /tmp/proxyfilter-vmess-blockers.json
```

### Результат локального запуска: 201 VMess URI

Локальный запуск анализатора от 2026-11-05 прошёл 2 unittest
(`OK`), прочитал `03-safe.jsonl` без повреждённых строк
(`invalid_checkpoint_rows=0`) и дал:

| Первичный отказ | URI |
|---|---:|
| Только `pcs` | **195** |
| Одновременно `pcs` и `ech` | **5** |
| Только `echConfigList` | **1** |
| **Всего** | **201** |

Итого: `pcs` — **200/201** (99,5%); `ech` — **5/201**;
`echConfigList` — **1/201**. Эти числа перекрываются по полям,
но комбинации образуют непересекающееся распределение.
Ни один из остальных членов `_UNSUPPORTED` не встретился
среди первых VMess отказов этой категории.

**Семантический вывод:** `pcs` в VMess legacy Base64(JSON) —
certificate pinning; нельзя преобразовывать его в
`tls.certificate_public_key_sha256` (другая сущность).
[Podkop LINKS.md, TLS](https://github.com/podkop-net/podkop-engine/blob/main/docs/LINKS.md)
тоже подтверждает несовместимость, **но политика его decode-link другая**:

| Контекст Podkop для `pcs` / `pinSHA256` | Поведение Podkop | Поведение нашего native experiment |
|---|---|---|
| `security=tls`, непустой pin, проверка сертификата включена, нет `cert` | **Принимает** ссылку, выдаёт `warning: the pinned certificate (pcs, pinSHA256) is not supported`, pin **не переносит**. Вместо pin проверка идёт по системным корням. Самоподписанный сертификат может не пройти | **Отказывает**: `unsupported_connection_field`, не маскирует потерю требования сертификата |
| `security=tls` с `allowInsecure=1` **или** передан `cert` | **Принимает**, pin не переносит **без предупреждения**; `allowInsecure` отключает обычную проверку, `cert` задаёт отдельный доверенный сертификат | **Отказывает** для любого присутствующего `pcs`, пока не доказана нейтральность сочетания |
| Нет TLS (`security=none`; для VMess/VLESS в Podkop отсутствие `security` по умолчанию означает none) | TLS-параметры, включая `pcs`, игнорируются **без предупреждения** | **Отказывает** на раннем `_UNSUPPORTED` независимо от наличия TLS |
| Пустой `pcs` | В таблице Podkop явно указан warning только для **непустого** значения; точное поведение пустого значения отдельно не установлено | **Отказывает** при наличии ключа, даже с пустым значением |

**Различие принципиальное:** Podkop выбирает `best effort + warning`
(иногда silent ignore), при этом пытается собрать работоспособный
outbound; `proxy-filter` придерживается `fail-closed` и не принимает
незаметную потерю certificate pin. **Успех Podkop не означает
семантической эквивалентности**. При `allowInsecure=1` или `cert`
отсутствие влияния pin — это утверждение реализации Podkop, а не
универсальный закон Xray/VMess.

В `proxyfilter/singbox_backend.py` уже стоит явный отказ для
`pcs` и `pinnedPeerCertSha256`. Возможное игнорирование `pcs`
целевым EXT не является доказательством эквивалентности.
Все 200 локальных URI по-прежнему относятся к **ранним отказам**;
этот аудит не определял их фактические `tls`/`security`,
`allowInsecure` и `cert` комбинации. Поэтому заранее нельзя
сказать, в скольких из них Podkop выдал бы warning, а в скольких
проигнорировал бы pin молча.

**Приоритет меняется:** эти 200 конфигураций невозможно объявить
`safe_native` простой правкой URI-mapper. Нужна проверка, что именно
закреплено в `pcs`, его кодирование и поддержка сертификатного pin
**конкретным** ядром; иначе отказы следует сохранить.
Для 6 записей ECH отдельно проверить формат (`ech` vs
`echConfigList`), вложенные настройки и совместимость ядра.
Никакие URI или значения pin в отчёт не выводить.

**Следующее решение зависит от полученных счётчиков.** Приоритетом
будет доминирующее семейство, но исправление допустимо только после
сверки отдельного URI-поля с нашей спецификацией, целевым
`sing-box-extended` и независимым источником. Без checkpoint
не приписывать 201 случаям конкретные поля или значения.

## Контекстный аудит `pcs` в VMess Base64(JSON) (2026-11-05)

**Основание:** в последнем локальном checkpoint из 201 VMess
`unsupported_connection_field` ровно **200 содержат `pcs`**
(195 только `pcs`, пять `pcs+ech`). Решение об игнорировании
pin **нельзя** принимать на основании одного имени поля.

### Разделение TLS, VMess security и certificate pin

В проверенном
[`sing-box-extended/parser/link/vmess.go`](https://github.com/dioxine/sing-box-extended/blob/extended/parser/link/vmess.go)
(`d3a09711efedaab6f567ae71765109f23614e391`)
VMess `tls` включает TLS только для точных строковых значений
`"1"`, `"true"`, `"tls"`; `insecure` и `skip-cert-verify`
включают обход проверки только для `"1"` или `"true"`.
Это **описание конкретного внешнего парсера**, не общее правило
нормализации и не основание переписывать нестроковые JSON-значения.
`scy`/`security` относятся к VMess cipher, не к TLS; присутствие
этих полей нужно учитывать отдельно, а не приравнивать к `tls=tls`.

[Podkop `docs/LINKS.md`, TLS](https://github.com/podkop-net/podkop-engine/blob/main/docs/LINKS.md)
использует другую политику:
(а) без TLS пропускает TLS-параметры;
(б) при активной проверке сертификата и непустом `pcs`
предупреждает, но игнорирует pin;
(в) при `allowInsecure=1` или наличии `cert` игнорирует pin
без предупреждения. Наш **fail-closed** не меняется.
Случай `cert` особенно требует доказательства: наличие сертификата
в ссылке ещё не доказывает, что конкретный сервер и клиент
применяют проверку, эквивалентную pinning.

### Диагностика без исходных значений

Добавлен read-only `tools/audit_vmess_pcs_context.py`:
он принимает тот же `03-safe.jsonl`, рассматривает **только** записи
VMess с **первым отказом** `unsupported_connection_field` и
ключом `pcs`, а в JSON отчёта возвращает:

| Счётчик | Что измеряет | Ограничение |
|---|---|---|
| `tls_state` | `absent`, `enabled_literal`, `disabled_literal`, `other_literal`, `non_string` | Точные литералы EXT, не сетевой TLS-тест |
| `insecure_state` | `absent`, `on`, `off`, `other`, `non_string`, `conflicting` для `insecure` и `skip-cert-verify` | Не объединять без доказательства с `allowInsecure` |
| `pin_state` | `empty_string`, `nonempty_string`, `null`, `non_string` | Отсутствуют длина, хеш, само значение |
| `other_fields` | Только наличие `cert`, `ech`, `echConfigList`, `security`, `scy` | Наличие `cert` ≠ проверенная работа сертификатного pin |
| `contexts` | Пересечения фиксированных категорий TLS, insecure, cert, pin, ECH | Ровно одна комбинация на URI; никаких произвольных имён полей |

Инструмент **не выводит** URI, хеши, сертификаты, значения,
адреса, ключи аутентификации и произвольные имена полей.
Сумма `contexts` должна равняться `rows`, а при прежнем
checkpoint ожидается `rows=200`. Численное распределение пока
**неизвестно**, до локального запуска ничего не приписываем.

Из каталога `app/`, после `git pull`:

```bash
python3 -m unittest tests.test_audit_vmess_pcs_context -v
python3 tools/audit_vmess_pcs_context.py \
  --checkpoint ../data/work/03-safe.jsonl \
  --output /tmp/proxyfilter-vmess-pcs-context.json
cat /tmp/proxyfilter-vmess-pcs-context.json
```

**Дальнейшее правило:** только если будет доказано, что конкретный
`pcs` нейтрален *для исходного URI и целевого backend*, можно
рассматривать узкое исключение. Даже для TLS `absent`/выключенного
одного факта недостаточно без проверки конфликтующих TLS-aliases
и поведения конкретного парсера. Прямое `pcs` →
`tls.certificate_public_key_sha256` **запрещено**.
Production mapping и `_UNSUPPORTED` остаются неизменными.

## VMess `pcs=""`: подтверждённая узкая нейтральность (2026-11-05)

**Фактический локальный результат** `tools/audit_vmess_pcs_context.py`:
`rows=200`, `invalid_checkpoint_rows=0`; все 200 имеют
`pin_state=empty_string` и `insecure_state=off`, все без `cert`.
Контексты (непересекающиеся):

| TLS | ECH | URI |
|---|---|---:|
| `disabled_literal` | отсутствует | **135** |
| `enabled_literal` | отсутствует | **60** |
| `disabled_literal` | есть `ech` | **5** |
| **Итого** | | **200** |

`scy` присутствует у всех 200, `security` отсутствует.
`scy` — шифр VMess и не определяет включение TLS.

**Доказательства для единственного исключения:**

1. В закреплённом
   [`sing-box-extended/parser/link/vmess.go`](https://github.com/dioxine/sing-box-extended/blob/extended/parser/link/vmess.go)
   (blob `d3a09711efedaab6f567ae71765109f23614e391`)
   VMess parser разбирает поля из явного `switch` и **не
   использует `pcs`**.
2. `pcs=""` — пустое значение pin, не задающее конкретного
   закреплённого сертификата. При включённом и выключенном TLS
   отсутствие поля не меняет значение pin.
3. `proxyfilter/singbox_backend.py` запрещает `pcs` по наличию
   ключа, а не значению. Поэтому для этого точного случая поле
   исключается **только во временном native mapping**,
   как сделано ранее для нейтрального VMess `cs=""`.

**Реализовано в эксперименте:** для VMess и **только** при
`type(params["pcs"]) is str and params["pcs"] == ""`
ключ `pcs` больше не вызывает общий `unsupported_connection_field`
и не учитывается как `unclassified loss`.
`params` и `original_raw` остаются без изменений.
Все непустые и нестроковые значения `pcs` отвергаются.
Все другие протоколы и aliases certificate pin остаются под
прежним запретом. При `pcs=""` плюс `ech` / `echConfigList`
отказ сохраняется по ECH; новые значения `fm` и прочих
connection-sensitive полей тоже блокируют результат.

**Отличие от Podkop:** он в ряде случаев игнорирует даже
**непустой** pin с warning или молча; PF по-прежнему не
разрешает непустые значения. Это исключение не является
переходом к `best effort`.

**Ожидаемая верхняя граница:** 195 ранее отклонённых VMess URI
могут пройти дальше первого gate (135 без TLS + 60 с TLS).
Пять с `ech` продолжат отвергаться, а иные проверки способны
сократить реальный прирост. Не утверждать `+195 safe_native`
до нового локального аудита. Это подтверждение нейтральности
конкретного URI-поля для целевого парсера, а не доказательство
совпадения поведения всех native transport/TLS реализаций.

Из `app/`:

```bash
python3 -m unittest tests.test_native_experiment tests.test_audit_native_coverage tests.test_audit_vmess_blockers tests.test_audit_vmess_pcs_context -v
python3 tools/audit_native_coverage.py \
  --checkpoint ../data/work/03-safe.jsonl \
  --output /tmp/proxyfilter-native-after-empty-pcs.json
jq '.protocols.vmess' /tmp/proxyfilter-native-after-empty-pcs.json
```

## Зафиксированные пробелы реализации и правила gate

1. **Версионная схема:** upstream JSON documentation может описывать поля после 1.14.3; получить version-specific schema и выполнить `sing-box check` установленным бинарником.
2. **Полнота протоколов:** это матрица известных встречающихся и реализованных полей; не нормативная «полная спецификация share URI». Для абсолютной полноты необходимы раздельные upstream/Xray/Clash/SIP002/HY2/TUIC specs и fixture corpus.
3. **Нельзя считать существующий PF converter строгим:** `singbox_modes.py` в production `standard` пробрасывает неизвестные URI keys как top-level JSON. `native_experiment.py` — отдельный opt-in и тоже пока не валидирует всё.
4. **Не классифицировать как безопасные неизвестные поля по одному отсутствию обработки в EXT.** Различать metadata, unrecognized extension, recognized-but-unsupported connection property.
5. **Никакого silent fallback:** нестандартный transport, unknown TLS, alias conflict, некорректная кодировка или неподдерживаемые свойства дают явный отказ/диагностику.
6. **A/B на совпадающих идентичностях:** baseline `original_raw` → `type=parser`; эксперимент URI → native JSON. Сравнивать `sing-box check`, network, latency, DL/UL, Exit IP, parsed-field diagnostics. Check PASS не доказывает semantic equivalence.
7. **Данные:** инвентаризацию по всем стадиям `01-parsed.jsonl`, `03-safe.jsonl`, `11-rejected-render.jsonl`, `14-published.jsonl` одного прогона выполнить на ноутбуке; опубликованные 67 — survivor-biased subset.

## Источники и код (для повторной сверки)

- sing-box [VLESS](https://sing-box.sagernet.org/configuration/outbound/vless/), [VMess](https://sing-box.sagernet.org/configuration/outbound/vmess/), [Trojan](https://sing-box.sagernet.org/configuration/outbound/trojan/), [Shadowsocks](https://sing-box.sagernet.org/configuration/outbound/shadowsocks/), [Hysteria2](https://sing-box.sagernet.org/configuration/outbound/hysteria2/), [TUIC](https://sing-box.sagernet.org/configuration/outbound/tuic/).
- sing-box [TLS](https://sing-box.sagernet.org/configuration/shared/tls/), [V2Ray transport](https://sing-box.sagernet.org/configuration/shared/v2ray-transport/).
- [sing-box-extended tag v1.14.3-extended-2.7.3](https://github.com/shtorm-7/sing-box-extended/tree/v1.14.3-extended-2.7.3/parser/link) и `docs/extended-link-parser-analysis.md` (предыдущий audit source).
- `proxyfilter/ingest.py`, `proxyfilter/engine.py`, `proxyfilter/singbox_backend.py`, `proxyfilter/singbox_modes.py`, `proxyfilter/native_experiment.py`.
- `docs/uri-native-json-audit.md`, `docs/native-converter-experiment.md`; `tools/audit_uri_fields.py`.

**Матрица является проектным контрактом исследования, а не разрешением переносить эксперимент в production.**
