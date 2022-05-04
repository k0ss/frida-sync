import { log } from "./logger";

let VERBOSE = 2;
function sleep(ms: number) {
    return new Promise(resolve => setTimeout(resolve, ms));
}

export class Tunnel
{
    private sock : SocketConnection | undefined;
    private sync: Boolean = false;
    constructor(host: string|undefined)
    {
        Socket.connect({
            host: host,
            port: 9100
        })
        .then(
            sock =>
            {
                log(`Connected!`);
                this.sock = sock;
                this.sync = true;
            },
            reason => 
            {
                log(`Failed`);
            }
        )
        .catch(
            reason =>
            {
                log(`[sync] Tunnel initialization error: ${reason}`);
                this.sync = false;
            }
        );
    }
    is_up(): Boolean
    {
        return this.sync && this.sock !== undefined;
    }
    poll() : string | null | undefined
    {
        let msg : string | null;
        if (! this.is_up())
        {
            return null;
        }
        this.sock?.input.read(4096)
        .then(
            value =>
            {
                return value.unwrap().readUtf8String();
            }
        )
        .catch(
            reason =>
            {
                log(`[sync] error on poll: ${reason}`);
                //TODO: original python script checks socket error for EAGAIN or EWOULDBLOCK and returns '\n' if so.
                this.sock?.close();
                return null;
            }
        );
    }
    send(msg : string)
    {
        if (typeof this.sock === undefined)
        {
            log(`[sync] tunnel_send: tunnel is unavailable (did you forget to sync ?)`);
            return;
        }
        this.sock?.output.writeAll(Array.from(msg).map(Number))
        .catch(
            reason =>
            {
                this.sync = false;
                this.close();
                log(`[sync] tunnel_send error: ${reason}`);
            }
        );
    }
    close()
    {
        if (this.is_up())
        {
            this.send("[notice]{\"type\":\"dbg_quit\",\"msg\":\"dbg disconnected\"}\n");
            if (typeof this.sock !== undefined)
            {
                this.sock?.close()
                .catch(
                    reason =>
                    {
                        log("[sync] tunnel_close error: ${reason}");
                    }
                );
                this.sync = false;
                this.sock = undefined;
            }
        }
    }

}

export class Rln
{
    private sync : Sync;
    constructor(sync : Sync)
    {
        this.sync = sync;
    }
    invoke(raddr : NativePointer | null)
    {
        this.sync.locate(raddr);
        
        if (raddr == null || this.sync.offset === undefined )
        {
            return "-"
        }
        this.sync.tunnel?.send("[sync]{\"type\":\"rln\",\"raddr\":${raddr}");
        sleep(500).finally(
            () =>
            {
                let msg = this.sync.tunnel?.poll();
                if (msg !== undefined && msg !== null)
                {
                    return msg.trimEnd();
                }
                else
                {
                    return "-";
                }
            }
        )
    }
}

export class Sync
{
    private host : string | undefined;
    private map : ModuleMap | undefined;
    private base : NativePointer | undefined;
    public offset : NativePointer | undefined;
    public tunnel : Tunnel | undefined;

    constructor(host: string|undefined)
    {
        this.map = new ModuleMap();
        this.host = host;
    }
    locate(offset: NativePointer | null)
    {
        if (offset === null)
        {
            log("<unknown offset>");
            return;
        }
        this.offset = offset;
        let mod = this.map?.find(offset);
        if (mod)
        {
            if (VERBOSE >= 2)
            {
                log(`[sync] mod found: ${mod.path} [${mod.base}]`);
            }
            if (this.base != mod.base)
            {
                this.tunnel?.send(`[notice]{\"type\":\"module\",\"path\":\"${mod.path}\"}\n`);
                this.base = mod.base;
            }
            this.tunnel?.send(`[sync]{\"type\":\"loc\",\"base\":${this.base},\"offset\":${this.offset}}\n`);
        }
        else
        {
            this.base = undefined;
            this.offset = undefined;
        }
    }
    invoke(offset: NativePointer | null)
    {
        if ( this.tunnel !== undefined && !this.tunnel.is_up() )
        {
            this.tunnel = undefined;
        }
        if ( this.tunnel === undefined )
        {
            this.tunnel = new Tunnel(this.host);
            if ( ! this.tunnel.is_up() )
            {
                log("[sync] sync failed");
                return;
            }
            let id = "ext_frida";
            this.tunnel.send(`[notice]{\"type\":\"new_dbg\",\"msg\":\"dbg connect - ${id}\",\"dialect\":\"gdb\"}\n`);
            log(`[sync] sync is now enabled with host ${this.host}`);
        }
        else
        {
            log("(update)");
        }
        return this.locate(offset);
    }
}