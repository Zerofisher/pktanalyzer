package uiadapter

var _ PacketReadStore = (*MemoryStore)(nil)
var _ PacketReadStore = (*IndexedStore)(nil)
var _ PacketFilterStore = (*MemoryStore)(nil)
var _ PacketFilterStore = (*IndexedStore)(nil)
var _ PacketAppendStore = (*MemoryStore)(nil)
var _ FlowQueryable = (*IndexedStore)(nil)
var _ EventQueryable = (*IndexedStore)(nil)
var _ PacketReceiver = (*MemoryStore)(nil)
