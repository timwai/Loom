// Independent WIRE-01 Kotlin/JVM canonical CBOR and signing transcript checks.
// No policy authorization or signature verification occurs in this file.
import java.io.File
import java.nio.ByteBuffer

private class Cursor(val bytes: ByteArray) {
    var pos = 0
    fun take(n: Int): ByteArray {
        require(n >= 0 && n <= bytes.size-pos)
        val out = bytes.copyOfRange(pos,pos+n)
        pos += n
        return out
    }
    fun head(major: Int): ULong {
        val marker = take(1)[0].toInt() and 255
        require(marker ushr 5 == major)
        val code = marker and 31
        if (code < 24) return code.toULong()
        require(code in 24..27)
        val n = when(code) { 24->1;25->2;26->4;else->8 }
        var value=0uL
        for (v in take(n)) value=(value shl 8) or (v.toInt() and 255).toULong()
        val floor=when(code){24->24uL;25->256uL;26->65536uL;else->4294967296uL}
        require(value>=floor)
        return value
    }
    fun number()=head(0)
    fun binary(max: Int): ByteArray {
        val n=head(2)
        require(n<=max.toULong())
        return take(n.toInt())
    }
    fun validate() {
        require(bytes.size<=65536)
        require(head(5)==9uL)
        var start=0uL
        var end=0uL
        for (k in 0..8) {
            require(number()==k.toULong())
            when(k) {
                0->require(number()==1uL)
                1->require(number() in 1uL..5uL)
                2->require(binary(16).size==16)
                3->require(binary(32).size==32)
                4,7->number()
                5->start=number()
                6->end=number()
                8->binary(61440)
            }
        }
        require(pos==bytes.size)
        require(start<end)
    }
}
private fun hexFile(root:String,name:String):ByteArray {
    val text=File(root,"test-vectors/wire-v1/$name").readText().trim()
    require(text.length%2==0)
    return ByteArray(text.length/2){i->text.substring(2*i,2*i+2).toInt(16).toByte()}
}
private fun reject(label:String,value:ByteArray) {
    check(runCatching{Cursor(value).validate()}.isFailure){"accepted $label"}
}
fun main(args:Array<String>) {
    val root=args.firstOrNull()?:"."
    val domain="LOOM:SECURITY-EVENT:V1".toByteArray()+byteArrayOf(0)
    for (name in listOf("event-01","event-02","event-03")) {
        val candidate=hexFile(root,"$name.cbor.hex")
        Cursor(candidate).validate()
        val size=ByteBuffer.allocate(4).putInt(candidate.size).array()
        check((domain+size+candidate).contentEquals(hexFile(root,"$name.signing.hex")))
    }
    val event=hexFile(root,"event-01.cbor.hex")
    for (n in 0 until event.size) reject("truncation",event.copyOfRange(0,n))
    val samples=mutableListOf<ByteArray>()
    fun flip(i:Int,v:Int){samples.add(event.copyOf().also{it[i]=v.toByte()})}
    flip(0,0xbf);flip(0,0xaa);flip(3,0);flip(2,2);flip(4,7)
    flip(0,0xc9);flip(25,0x1f)
    samples.add(event+byteArrayOf(0))
    samples.add(event.copyOfRange(0,2)+byteArrayOf(0x18,0x01)+event.copyOfRange(3,event.size))
    samples.forEach {reject("negative",it)}
    println("WIRE-01 Kotlin PASS: canonical transcript, ${event.size} truncations, ${samples.size} negative cases")
}
