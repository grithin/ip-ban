from typing import Optional
from sqlalchemy import ForeignKey, UniqueConstraint
from sqlalchemy import Date, Boolean, Integer
from sqlalchemy.orm import DeclarativeBase
from sqlalchemy.orm import Mapped
from sqlalchemy.orm import mapped_column

class Base(DeclarativeBase):
    pass

class IpLogFiles(Base):
    __tablename__ = "ip_log_file"
    id: Mapped[int] = mapped_column(primary_key=True, autoincrement=True)
    file: Mapped[Optional[str]]
    date: Mapped[str] = mapped_column(Date)
    def __repr__(self) -> str:
        return f"IpLogFiles(id={self.id!r}, file={self.file!r}, date={self.date!r})"

class IpLog(Base):
    __tablename__ = "ip_log"
    id: Mapped[int] = mapped_column(primary_key=True, autoincrement=True)
    ip: Mapped[int]
    date: Mapped[str] = mapped_column(Date)
    reason: Mapped[Optional[str]]
    processed: Mapped[bool] = mapped_column(Boolean, default=False)
    file_id: Mapped[Optional[int]] = mapped_column(Integer, ForeignKey('ip_log_file.id'), nullable=True)
    def __repr__(self) -> str:
        return f"IpLog(id={self.id!r}, date={self.date!r}, reason={self.reason!r})"

class CidrScore(Base):
    __tablename__ = "cidr_score"
    id: Mapped[int] = mapped_column(primary_key=True, autoincrement=True)
    ip_start: Mapped[int]
    net: Mapped[int]
    marks: Mapped[int]
    block16_marks: Mapped[int] = mapped_column(default=0)
    __table_args__ = (
        UniqueConstraint('ip_start', 'net', name='uq_cidr_score'),
    )
    def __repr__(self) -> str:
        return f"CidrScore(id={self.id!r}, ip_start={self.ip_start!r}, net={self.net!r}, marks={self.marks!r})"

class CidrBan(Base):
    __tablename__ = "cidr_ban"
    id: Mapped[int] = mapped_column(primary_key=True, autoincrement=True)
    ip_start: Mapped[int]
    net: Mapped[int]
    cidr_string: Mapped[str]
    date: Mapped[str] = mapped_column(Date)
    __table_args__ = (
        UniqueConstraint('ip_start', 'net', name='uq_cidr_ban'),
    )
    def __repr__(self) -> str:
        return f"CidrBan(id={self.id!r}, cidr={self.cidr_string!r}, date={self.date!r})"

class IpWhitelist(Base):
    __tablename__ = "ip_whitelist"
    id: Mapped[int] = mapped_column(primary_key=True, autoincrement=True)
    ip_start: Mapped[int]
    net: Mapped[int]
    cidr_string: Mapped[str]
    note: Mapped[Optional[str]]
    date: Mapped[str] = mapped_column(Date)
    __table_args__ = (
        UniqueConstraint('ip_start', 'net', name='uq_ip_whitelist'),
    )
    def __repr__(self) -> str:
        return f"IpWhitelist(id={self.id!r}, cidr={self.cidr_string!r}, note={self.note!r})"

class CidrListFile(Base):
    __tablename__ = "cidr_list_file"
    id: Mapped[int] = mapped_column(primary_key=True, autoincrement=True)
    file: Mapped[str]
    date: Mapped[str] = mapped_column(Date)
    def __repr__(self) -> str:
        return f"CidrListFile(id={self.id!r}, file={self.file!r}, date={self.date!r})"

class CidrExternal(Base):
    __tablename__ = "cidr_external"
    id: Mapped[int] = mapped_column(primary_key=True, autoincrement=True)
    ip_start: Mapped[int]
    net: Mapped[int]
    cidr_string: Mapped[str]
    file_id: Mapped[int] = mapped_column(Integer, ForeignKey('cidr_list_file.id'))
    __table_args__ = (
        UniqueConstraint('ip_start', 'net', 'file_id', name='uq_cidr_external'),
    )
    def __repr__(self) -> str:
        return f"CidrExternal(id={self.id!r}, cidr={self.cidr_string!r})"
