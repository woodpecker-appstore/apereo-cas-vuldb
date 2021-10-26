package me.gv7;

import static org.junit.Assert.assertTrue;

import me.gv7.jevilcode.utils.CryptUtil;
import org.junit.Test;

/**
 * Unit test for simple App.
 */
public class AppTest 
{
    /**
     * Rigorous Test :-)
     */
    @Test
    public void shouldAnswerWithTrue() throws Exception {
        //String urldns = CommonUtil.generate("URLDNS", "http://xxx.dnslog.cn");
        //System.out.println(urldns);
        System.out.println(CryptUtil.decrypt("FYyPIekSGUo=", "ngrbcrzg"));
    }
}
