
# *** NL2XLOG version ***

# DB for FlatFile Watching: NGINX logfiles.
# Logfiles indexed by their inodes, though filenames are
#   stored too.
# Note: There's a similar, but different, same-named module for 
#       xlog2db.

import sqlite3, json
from l_misc import tblineno

# 160105: 'historical' -> 'static', added 'extra'
FNS = ('inode', 'ae', 'modified', 'size', 'acquired', 'processed', 'static', 'filename', 'extra')   


class FFWDB():

    def __init__(self, ffwdbpfn):
        self.ffwdbpfn = ffwdbpfn
        self.db = sqlite3.connect(self.ffwdbpfn)
        self.db.execute("""
            create table if not exists logfiles (
                inode       integer,
                ae          text,
                modified    real,
                size	    integer,
                acquired    real,
                processed	integer,
                static  	integer,
                filename    text,
                extra       text)
        """)
    
    def disconnect(self):
        try:  self.db.close()
        except:  pass
        
    def count(self, inode=None):
        try:
            csr = self.db.cursor()
            if inode:
                csr.execute('select count(*) from logfiles where inode=?', (inode, ))
            else:
                csr.execute('select count(*) from logfiles')
            try:  return csr.fetchone()[0]
            except:  return None
        except Exception as E:
            errmsg = 'FFWDB.count: %s @ %s' % (E, tblineno())
            raise RuntimeError(errmsg)
        finally:
            self.db.commit()

    def all(self):
        fis = []
        try:
            self.db.row_factory = sqlite3.Row
            csr = self.db.cursor()
            csr.execute('select * from logfiles where inode>0')
            for z in csr:
                fi = {}
                fi.update(z)
                fis.append(fi)
            return fis
        except Exception as E:
            errmsg = 'FFWDB.all: %s @ %s' % (E, tblineno())
            raise RuntimeError(errmsg)
        finally:
            self.db.commit()
        
    def select(self, inode):
        try:
            self.db.row_factory = sqlite3.Row
            csr = self.db.cursor()
            csr.execute('select * from logfiles where inode=?', (inode, ))
            z = csr.fetchone()
            if not z:
                return None
            fi = {}
            fi.update(z)
            return fi
        except Exception as E:
            errmsg = 'FFWDB.select: %s @ %s' % (E, tblineno())
            raise RuntimeError(errmsg)
        finally:
            self.db.commit()
        
    def inodes(self):
        try:
            csr = self.db.cursor()
            csr.execute('select inode from logfiles where inode>0')
            return [z[0] for z in csr]
        except Exception as E:
            errmsg = 'FFWDB.inodes: %s @ %s' % (E, tblineno())
            raise RuntimeError(errmsg)
        finally:
            self.db.commit()
        
    '''???
    def filenames(self):
        try:
            csr = self.db.cursor()
            csr.execute('select filename from logfiles order by modified')
            try:  return [z[0] for z in csr.fetchall()]
            except:  return []
        finally:
            self.db.commit()
    ???'''

    def insert(self, fi):
        try:
            inode = fi['inode']
            if self.count(inode):
                raise ValueError('FFWDB.insert: %d already in db' % (inode))
            ks, qs, vs = [], [], []
            for k, v in fi.items():
                ks.append(k)
                qs.append('?')
                vs.append(v)
            sql = 'insert into logfiles (%s) values (%s)' % (', '.join(ks), ', '.join(qs))
            csr = self.db.cursor()
            csr.execute(sql, vs)
        except Exception as E:
            errmsg = 'FFWDB.insert: %s @ %s' % (E, tblineno())
            raise RuntimeError(errmsg)
        finally:
            self.db.commit()
            return self.select(inode)
        
    def update(self, fi):
        try:
            inode = fi['inode']
            if not self.count(inode):
                raise ValueError('FFWDB.update: %d not in db' % (inode))
            kvs, vs = '', []
            for k, v in fi.items():
                if k == 'inode':
                    continue
                if kvs:
                    kvs += ', '
                kvs += (k + '=?')
                vs.append(v)
            vs.append(inode)
            sql = 'update logfiles set %s where inode=?' % kvs
            csr = self.db.cursor()
            csr.execute(sql, vs)
        except Exception as E:
            errmsg = 'FFWDB.update: %s @ %s' % (E, tblineno())
            raise RuntimeError(errmsg)
        finally:
            self.db.commit()
            return self.select(inode)
        
    def delete(self, inode):
        try:
            csr = self.db.cursor()
            csr.execute('delete from logfiles where inode=?', (inode, ))
        except Exception as E:
            errmsg = 'FFWDB.delete: %s @ %s' % (E, tblineno())
            raise RuntimeError(errmsg)
        finally:
            self.db.commit()
        
    def oldest(self, unfinished=True):
        try:
            self.db.row_factory = sqlite3.Row
            csr = self.db.cursor()
            if unfinished:
                csr.execute('select * from logfiles where (processed < size) order by modified asc limit 1')
            else:
                csr.execute('select * from logfiles order by modified desc limit 1')
            z = csr.fetchone()
            if not z:
                return None
            z = csr.fetchone()
            if not z:
                return None
            fi = {}
            fi.update(z)
            return fi
        except Exception as E:
            errmsg = 'FFWDB.oldest: %s @ %s' % (E, tblineno())
            raise RuntimeError(errmsg)
        finally:
            self.db.commit()

    def acquired(self, inodes, ts):
        # A bulk 'acquired' timestamp update bcs updates are slow.
        if not (inodes and ts):
            return
        try:
            csr = self.db.cursor()
            if len(inodes) == 1:
                sql = 'update logfiles set acquired=? where inode=%d' % (inodes[0])
            else:
                sql = 'update logfiles set acquired=? where inode in %s' % (str(inodes))
            csr.execute(sql, (ts, ))
        except Exception as E:
            errmsg = 'FFWDB.acquired: %s @ %s' % (E, tblineno())
            raise RuntimeError(errmsg)
        finally:
            self.db.commit()
        
    def extra(self, extra=None):
        try:
            # Return db.extra?
            if extra is None:
                csr = self.db.cursor()
                csr.execute('select extra from logfiles where inode=-1')
                z = csr.fetchone()
                if not z:
                    return {}
                rd = json.loads(z[0])
                return rd
            # Update db.extra?
            else:
                csr = self.db.cursor()
                csr.execute('select extra from logfiles where inode=-1')
                z = csr.fetchone()
                if not z:
                    csr.execute('insert into logfiles (inode, extra) values (?, ?)', (-1, ''))
                '''...
                csr.execute('select extra from logfiles where inode=-1')
                z = csr.fetchone()[0]
                ...'''
                z = json.dumps(extra)
                csr.execute('update logfiles set extra=? where inode=?', (z, -1))
                rd = self.extra()
                return rd
        except Exception as E:
            errmsg = 'FFWDB.extra: %s @ %s' % (E, tblineno())
            raise RuntimeError(errmsg)
        finally:
            self.db.commit()
