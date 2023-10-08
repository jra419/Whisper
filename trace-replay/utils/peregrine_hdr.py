from scapy.all import Packet, IntField, ByteField, LongField, Emph, SourceIPField, IEEEDoubleField


class WhisperPeregrineHdr(Packet):
    name = 'peregrine'
    fields_desc = [Emph(SourceIPField('ip_src', 0)),
                   ByteField('ip_proto', 0),
                   IntField('length', 0),
                   IEEEDoubleField('timestamp', 0)]
