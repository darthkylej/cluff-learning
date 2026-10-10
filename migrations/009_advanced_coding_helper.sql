-- Register Advanced Coding Helper. Run once against the Neon database.
INSERT INTO tools (slug,name,tagline,description,glyph,accent,status,url,sort_order)
VALUES ('advanced-coding-helper','Advanced Coding Helper','AI software engineering assistant',
'Chat about programming, databases, debugging, APIs, and building applications.',
'⌘','cyan','online','https://darthkylej.github.io/cluff-learning/advanced-coding-helper.html',45)
ON CONFLICT (slug) DO UPDATE SET name=EXCLUDED.name,tagline=EXCLUDED.tagline,
description=EXCLUDED.description,glyph=EXCLUDED.glyph,accent=EXCLUDED.accent,
status=EXCLUDED.status,url=EXCLUDED.url,sort_order=EXCLUDED.sort_order;
