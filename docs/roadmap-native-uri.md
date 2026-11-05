# Roadmap: URI → native sing-box JSON

**Проект:** `geser2008/proxy-filter`  
**Рабочая ветка:** `feature/protocol-native-parser`  
**Дата фиксации:** 2026-11-05  
**Статус:** рабочий план; задачи выполняются поэтапно, изменения небольшими логическими коммитами.

## Цель и границы

Завершить экспериментальный конвертер URI → native sing-box JSON с сохранением значимых для подключения параметров, отказом на неподдерживаемых или неоднозначных настройках и возможностью сравнить результат с исходным `type=parser`.

Production ingest принимает **TXT / Base64(TXT) → URI**: VLESS, VMess (legacy Base64(JSON)), Trojan, Shadowsocks, Hysteria2/hy2, TUIC. Clash YAML, sing-box JSON и Xray/V2Ray JSON **не являются production input**.

**Инварианты:**

- `original_raw` сохраняется verbatim; исходные `params`, identity, дедупликация и SQLite не меняются экспериментальным преобразованием.
- Нельзя исправлять некорректные URI/percent-encoding/Base64, угадывать отсутствующие значения или автоматически заменять неподдерживаемые транспорты.
- Unknown/vendor/future поля сохраняются в источнике; в эксперименте классифицируются без публичной утечки значений. Неизвестное поле не считается безопасным только потому, что другой parser его игнорирует.
- Certificate pin, ECH, REALITY, TLS verification и сетевые настройки не отбрасываются без доказательства эквивалентности.
- `safe_native` означает отсутствие **неклассифицированных потерь** в рамках текущего аудита; не означает `sing-box check PASS`, network PASS или одинаковый wire protocol.
- Реальные тесты и аудиты запускаются на ноутбуке из `app/`, **без `sudo -u proxyfilter`**. В GitHub коммитятся код, тесты, методика и результаты, которые действительно подтверждены.
- Сначала аудит и контракт, затем реализация и тестирование, затем обновление матрицы. Discussion ≠ поручение изменять production.

Основной контракт и сравнительный анализ: [`protocol-uri-to-singbox-matrix.md`](protocol-uri-to-singbox-matrix.md). Эксперимент и A/B: [`native-converter-experiment.md`](native-converter-experiment.md).

## Измеренный baseline (последний подтверждённый полный локальный аудит)

Checkpoint: `../data/work/03-safe.jsonl`, 8 848 URI, `invalid=0`.

| Показатель | Все URI | VMess |
|---|---:|---:|
| Всего | 8 848 | 546 |
| `safe_native` | 6 523 | 250 |
| `lossy_native` | 44 | 2 |
| `rejected` | 2 281 | 294 |

VMess first-rejections: `transport_fields_on_tcp=168`, `unsupported_vmess_header=118`, `unsupported_connection_field=6`, `unsupported_transport=2`.

**Оговорка:** указанные числа получены **до** коммита `eb9ea975`, разрешающего строго пустые TCP placeholders VMess. После него полного локального аудита ещё не было. Не приписывать этому изменению неподтверждённый прирост.

## План: порядок и условия завершения

### A. Закрыть VMess — текущий основной workstream

- [ ] **A1. Зафиксировать baseline после empty TCP placeholders.**
  - `git pull`, unit tests `tests.test_native_experiment`, `tests.test_audit_vmess_tcp_fields`.
  - Запустить `tools/audit_native_coverage.py` на том же `03-safe.jsonl`; сохранить полные итоги VMess и причины отказа.
  - **Done:** нет ошибок тестов; известны реальные изменения `safe/lossy/rejected`; статистика перенесена в матрицу.
- [ ] **A2. Разобрать непустые `host/path` при VMess plain TCP.**
  - Верифицировать `net=tcp`, `type=none/""/absent` по целевому `sing-box-extended`, Podkop, v2rayN и другим проверенным источникам.
  - Различить активные значения, неактивные transport placeholders и риск несовпадения URI dialect; не переносить правила `net=tcp` на WS/gRPC/H2.
  - Если нейтральность доказана — минимальный экспериментальный mapping и проверки сохранения source; для неоднозначных случаев оставить отказ.
  - **Done:** каждый рассмотренный контекст имеет обоснованное действие, тест, комментарий и measured coverage.
- [ ] **A3. Классифицировать 118 `unsupported_vmess_header`.**
  - Read-only агрегированный audit: `net × type × TLS`, контекстные формы gRPC `type=multi` и прочие header modes, без URI и секретов.
  - Отличать `type` в VMess Base64(JSON) от VLESS/Trojan `type`; не «исправлять» gRPC mode и HTTP-disguise.
  - **Done:** стабильные категории и причины для всех 118 первых отказов; поддерживаемые случаи подтверждены fixtures.
- [ ] **A4. Разобрать остаток VMess.**
  - `unsupported_connection_field` (6), `unsupported_transport` (2), два `lossy_native`; выявить причины и оценить необходимость поддержки.
  - Непустые `pcs`, ECH, несовместимые транспорты могут остаться `unsupported`: это корректный исход, если причина документирована.
  - **Done:** нет необъяснённых отказов/потерь в checkpoint; все причины привязаны к version-specific контракту.
- [ ] **A5. VMess A/B и завершение.**
  - На одной совместимой версии ядра сравнить исходный URI (`type=parser`) и native JSON: `sing-box check`, outbound shape, релевантные сетевые пробы, TLS/transport; результаты отдельно от классификации потерь.
  - **Done:** VMess закрыт по семантическим классам, ошибочные silent drops отсутствуют; остаточные ограничения явны. **Не требовать 100% `safe_native` как самоцель.**

Команды для A1, из `app/`:

```bash
python3 -m unittest \
  tests.test_native_experiment \
  tests.test_audit_vmess_tcp_fields -v

python3 tools/audit_native_coverage.py \
  --checkpoint ../data/work/03-safe.jsonl \
  --output /tmp/proxyfilter-native-after-tcp.json

jq '.protocols.vmess' /tmp/proxyfilter-native-after-tcp.json
```

### B. Проверить возможные ошибки production ingest (приоритет выше расширения coverage)

- [ ] **B1. Hysteria2 userinfo:** официальный формат может содержать `user:password` как **единый auth**. Проверить, не разбивает ли общий `ingest.parse_uri` значение на отдельные поля с потерей username. Добавить тесты с percent-escaped вариантами.
- [ ] **B2. Hysteria2 multiport authority:** проверить официальную форму с портами/диапазонами; текущий путь через `parts.port` не представляет многопортовый authority. Проверить отсутствие ложного принятия/потери hopping.
- [ ] **B3. Security invariants:** `pinSHA256`, `ech`, `sni`, `insecure` при HY2; нельзя принять соединение с ослабленной проверкой, если pin был отброшен.
- **Done:** реальные дефекты подтверждены тестами и исправлены отдельными коммитами, либо риски закрыты отрицательными тестами; production behavior и миграционные последствия зафиксированы. Не исправлять по одному предположению.

### C. Завершить VLESS и Trojan

- [ ] VLESS: REALITY `flow/pbk/sid/fp`, активность TLS, конфликты `sni/peer/serviceName`, WS early data, HTTP/H2, HTTPUpgrade, XHTTP `extra` и ALPN.
- [ ] Trojan: TLS по умолчанию против `security=none`, различие `serviceName` и `grpc-service-name`, Host/SNI, TCP HTTP-disguise и запрет скрытой смены HTTP/1.1 → HTTP/2.
- [ ] Для каждого протокола: first-rejection census → точечные fixtures → version-specific mapping → A/B.
- **Done:** классифицированы все потери и отказы реального checkpoint; нет непроверенного fallback или silent security downgrade.

### D. Завершить Shadowsocks, Hysteria2 и TUIC

- [ ] SS: SIP002/legacy Base64, корректный userinfo для AEAD-2022, SIP003 plugin/options и escaping, конфликты `plugin_opts`, методы и параметры UDP.
- [ ] HY2 native: сохранение auth, multiport/port hopping, `obfs` и зависимого пароля, bandwidth units, TLS/pinning/ECH; отдельно от работ B по production ingest.
- [ ] TUIC v5: UUID/password, v4 `token` как неподдерживаемый dialect, `udp_over_stream × udp_relay_mode`, 0-RTT aliases, heartbeat/duration, TLS/ALPN, QUIC extensions.
- **Done:** все существенные входные поля имеют контекстную классификацию и негативные fixtures; отсутствует доказанная потеря действующих свойств соединения.

### E. Общая независимая валидация и решение о production

- [ ] Повторить read-only coverage на одном согласованном checkpoint всех шести семейств, сравнить с исходным baseline.
- [ ] Выполнить `sing-box check` / A-B на реально установленном бинарнике, зафиксировать версии, build tags, transport/TLS mismatch и network results.
- [ ] Проверить отсутствие секретов в отчётах, изменения исходных данных и истории; прогнать регрессии ingest, normalization, render, identity.
- [ ] Обновить протокольную матрицу, включить явно неподдерживаемые случаи и критерии отказа.
- [ ] **Только после этого** отдельным решением рассматривать opt-in production-внедрение native JSON. Автоматический fallback не должен скрывать ошибки mapper.

## Ритм и критерии качества каждого шага

1. **Evidence first:** текущий GitHub-код и источник URI/spec/version, а не предположения и одни лишь совпадающие имена полей.
2. **Read-only census:** реальное количество записей и комбинаций; отчёты без endpoint/URI/пароля и произвольных значений.
3. **Контекстный контракт:** `protocol + format + transport + TLS/security + field/value type` → `mapped / neutral / rejected / gap`.
4. **Минимальный коммит:** один узкий change-set на код, тесты, документацию; при необходимости независимые коммиты.
5. **Локальный прогон пользователя:** unit tests, audit и — когда требуется — внешний `sing-box`; в документации различать **подтверждено** и **ожидается**.
6. **DoD:** тесты прошли, checkpoint измерен, source не мутирован, не обнаружено silent semantic loss, матрица обновлена.

## Порядок реагирования на риски

**P0:** подтверждённая порча/потеря auth, TLS verification/pin, port hopping либо неправильный parse в production.  
**P1:** wire-semantics и конфликты транспортных параметров, сначала VMess, далее VLESS/Trojan.  
**P2:** дополнительные URI vendor options без доказанного runtime влияния.

Дополнительные источники: [матрица](protocol-uri-to-singbox-matrix.md), [аудит целевого link parser](extended-link-parser-analysis.md), [native эксперимент и A/B](native-converter-experiment.md), [аудит URI→JSON](uri-native-json-audit.md).
