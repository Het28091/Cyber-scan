import json,sqlite3
from pathlib import Path
from .security import redact

class Store:
    def __init__(self,root):
        self.root=Path(root);self.root.mkdir(parents=True,exist_ok=True,mode=0o700)
        path=self.root/'runs.sqlite3'
        self.db=sqlite3.connect(path);path.chmod(0o600)
        version=self.db.execute('PRAGMA user_version').fetchone()[0]
        if version>1: raise ValueError('database schema is newer than this application')
        if version==0:
            with self.db:
                self.db.execute('CREATE TABLE runs(id TEXT PRIMARY KEY, status TEXT NOT NULL, data TEXT NOT NULL)')
                self.db.execute('PRAGMA user_version=1')
    def save(self,run):
        with self.db: self.db.execute('INSERT OR REPLACE INTO runs VALUES(?,?,?)',(run['id'],run['status'],json.dumps(redact(run))))
    def recover(self,ident=None):
        with self.db:
            query="SELECT id,data FROM runs WHERE status='RUNNING'"
            rows=self.db.execute(query+' AND id=?',(ident,)).fetchall() if ident is not None else self.db.execute(query).fetchall()
            for ident,raw in rows:
                run=json.loads(raw);run['status']='INTERRUPTED';run['events'].append('Interrupted assessment recovered; use resume to regenerate partial reports.')
                self.db.execute('UPDATE runs SET status=?,data=? WHERE id=?',('INTERRUPTED',json.dumps(run),ident))
    def get(self,ident):
        row=self.db.execute('SELECT data FROM runs WHERE id=?',(ident,)).fetchone()
        if not row: raise ValueError('unknown run ID')
        return json.loads(row[0])
