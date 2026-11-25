MATCH p=(e:Method)-[:CALL|ALIAS* SHORTEST 1..12]->(s:Method)
WHERE e.name IN $entries AND e.cls <> 'java.io.ObjectInputStream' AND s.is_sink = 'TRUE' AND s.vul <> ''
RETURN e.cls AS entry_cls, e.name AS entry_name,
       s.cls AS sink_cls, s.name AS sink_name, s.vul AS vul,
       length(p) AS depth, p
ORDER BY depth ASC
LIMIT $limit
