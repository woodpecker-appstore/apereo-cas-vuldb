package me.gv7.woodpecker.plugin.payloads;

import me.gv7.woodpecker.plugin.*;
import org.cryptacular.bean.BufferedBlockCipherBean;
import org.cryptacular.bean.KeyStoreFactoryBean;
import org.cryptacular.generator.sp80038a.RBGNonce;
import org.cryptacular.io.URLResource;
import org.cryptacular.spec.BufferedBlockCipherSpec;
import me.gv7.woodpecker.tools.codec.BASE64Decoder;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.net.URL;
import java.net.URLDecoder;
import java.security.KeyStore;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.zip.GZIPInputStream;

public class CasPayloadDecoder implements IPayloadGenerator {
    @Override
    public String getPayloadTabCaption() {
        return "CAS execute decoder";
    }

    @Override
    public IArgsUsageBinder getPayloadCustomArgs() {
        IArgsUsageBinder binder = CasRCE.callbacks.getPluginHelper().createArgsUsageBinder();
        final List<IArg> args = new ArrayList<IArg>();
        final IArg gadge = CasRCE.pluginHelper.createArg();
        gadge.setName("execute");
        gadge.setDefaultValue("39a0a1ff-9397-499b-b419-3094da3ac42f_AAAAIgAAA...");
        gadge.setDescription("execute参数值");
        gadge.setRequired(true);
        args.add(gadge);
        binder.setArgsList(args);
        return binder;
    }

    @Override
    public void generatorPayload(Map<String, Object> customArgs, IResultOutput resultOutput) {
        String execute = (String)customArgs.get("execute");

        execute = new URLDecoder().decode(execute);
        if(execute.indexOf("_AAAA")== -1){
            resultOutput.failPrintln("It's not the right data,not found _AAAA");
            return;
        }
        String base64Data = execute.substring(execute.indexOf("_AAAA")+1);

        byte[] decryptData = new byte[0];

        try {
            decryptData = decryptCASExecute(base64Data);
        } catch (Exception e) {
            resultOutput.errorPrintln(CasRCE.pluginHelper.getThrowableInfo(e));
            return;
        }
        resultOutput.successPrintln("Decode payload success");
        resultOutput.rawPrintln("\n");
        resultOutput.rawPrintln(new String(decryptData));
        resultOutput.rawPrintln("\n");
    }

    public static byte[] decryptCASExecute(String execute) throws Exception{
        byte[] encodeByte = new BASE64Decoder().decodeBuffer(execute);
        KeyStoreFactoryBean ksFactory = new KeyStoreFactoryBean();
        URL u = CasPayloadDecoder.class.getClassLoader().getResource("etc/keystore.jceks");
        ksFactory.setResource(new URLResource(u));
        ksFactory.setType("JCEKS");
        ksFactory.setPassword("changeit");
        KeyStore keyStore = ksFactory.newInstance();
        BufferedBlockCipherBean bufferedBlockCipherBean = new BufferedBlockCipherBean();
        bufferedBlockCipherBean.setBlockCipherSpec(new BufferedBlockCipherSpec("AES", "CBC", "PKCS7"));
        bufferedBlockCipherBean.setKeyStore(keyStore);
        bufferedBlockCipherBean.setKeyAlias("aes128");
        bufferedBlockCipherBean.setKeyPassword("changeit");
        bufferedBlockCipherBean.setNonce(new RBGNonce());
        byte[] chiper = bufferedBlockCipherBean.decrypt(encodeByte);

        ByteArrayInputStream inBuffer = new ByteArrayInputStream(chiper);
        GZIPInputStream gzipInputStream = new GZIPInputStream(inBuffer);

        ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
        byte[] buff = new byte[255];
        int n;
        while ((n = gzipInputStream.read(buff)) != -1){
            outputStream.write(buff);
        }
        return outputStream.toByteArray();
    }
}
