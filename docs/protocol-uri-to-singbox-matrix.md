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
| `global_padding`, `authenticated_length` | одноимённые boolean | C | в legacy VMess URI часто отсутствуют, отсутствие ≠ explicit false | EXT [M1] |
| `packetEncoding` | `packet_encoding` | C | зависит от parser implementation | EXT [M1] |
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
| `plugin_opts`, `plugin-opts` | `plugin_opts` | C | конфликт с уже раскрытым `plugin=...;opts` → диагностировать | EXT [S1] |
| `network` | `network` | C | `tcp`/`udp` допустимы; не путать с `type` V2Ray transport | EXT [S1] |
| `udp_over_tcp` | `udp_over_tcp` | C | boolean/object по схеме установленного ядра | EXT [S1] |
| `multiplex` | `multiplex` | C | JSON object; не считать частью URI SIP002 без подтверждения | EXT [S1] |
| `type=tcp`, `headerType=none` | нет собственного SS transport | C | только доказанная render-neutral metadata, не добавлять transport object | OBSERVED |
| неизвестные поля | нет | GAP | EXT SS link handler обрабатывает минимальный набор | OBSERVED [S1] |

## Hysteria2 / hy2

| URI поле | JSON назначение | Статус | EXT / PF / ограничения | Происхождение / источник |
|---|---|---|---| --- |
| userinfo / `auth` | `password` | C | требуется отсутствие противоречий `password/auth` | SPEC [H1] |
| authority порт / `mport`, `ports`, `server_ports` | `server_port` или `server_ports` | C | server_ports — диапазоны, JSON `2080:3000`; порт hopping без потерь | SPEC/EXT [H1] |
| `hop_interval`, `hop_interval_max` | одноимённые duration | C | число и единицы нельзя угадывать | EXT [H1] |
| `up`/`down`, `up_mbps`/`down_mbps` | integer Mbps | C | PF отвергает нецелое Mbps; EXT может проигнорировать ошибку | EXT [H1] |
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
| `UUID:password@` | `uuid`, `password` | M | обязательный UUID; password проверять отдельно | EXT [U1] |
| `congestion_control` / `congestion-controller` | `congestion_control` | C | проверить разрешённые `cubic/new_reno/bbr` | OBSERVED [U2] |
| `udp_relay_mode` | `udp_relay_mode` | C | не путать с `udp_over_stream` | OBSERVED [U2] |
| `udp_over_stream` | `udp_over_stream` | C | EXT может очищать relay mode при true, требуются fixtures | OBSERVED [U2] |
| `zero_rtt_handshake` / `reduce-rtt` | `zero_rtt_handshake` | C | строгий bool | OBSERVED [U2] |
| `heartbeat`, `heartbeat_interval` | `heartbeat` duration | C | секунды vs миллисекунды; не допускать конфликта | OBSERVED [U2] |
| `sni`, `alpn`, `insecure` | `tls` | C | static security gate | OBSERVED [U2] |
| `fingerprint` (certificate) | **не** `tls.utls.fingerprint` | GAP | различить с `fp` (uTLS) | OBSERVED [U1] |
| `token` | TUIC v4 legacy auth | GAP | текущий PF mapper отвергает; не трактовать как TUIC v5 | LEGACY [U1] |
| `network`, QUIC параметры | `network` / QUIC fields | C | проверка версии ядра и схемы | OBSERVED [U2] |


### Ссылки классификации происхождения URI (проверены 2026-11-05)

- **[V1]** [XTLS/Xray-core #716 — VMessAEAD / VLESS share-link proposal](https://github.com/XTLS/Xray-core/discussions/716). Это **предложение URI**, а не общеобязательный стандарт каждого Xray-расширения.
- **[V2]** [Material Xray — VLESS share-link conventions](https://materialxray.app/docs/reference/share-links/). Документация конкретной реализации; поля XHTTP/REALITY и прочие расширения должны иметь версионный контекст.
- **[M1]** [v2rayN Wiki — Description of VMess share link](https://github.com/2dust/v2rayN/wiki/Description-of-VMess-share-link). Документирован именно legacy формат `vmess://Base64(JSON)`, не VMessAEAD URL с query.
- **[T1]** [Potatso — Trojan share URI](https://docs.potatso.com/protocols/trojan/). Описывает клиентское представление `trojan://` и Xray-совместимые дополнения; это не спецификация сетевого Trojan-протокола.
- **[S1]** [Shadowsocks — SIP002 URI scheme](https://shadowsocks.org/doc/sip002.html). Нормативное описание ссылки, `plugin`, структуры userinfo и правил percent/Base64URL encoding.
- **[H1]** [Hysteria2 — official URI Scheme](https://v2.hysteria.network/docs/developers/URI-Scheme/). Нормативные поля `obfs`, `obfs-password`, `sni`, `insecure`, `pinSHA256`, `ech`; bandwidth исключён намеренно.
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
