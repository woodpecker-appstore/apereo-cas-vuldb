package me.gv7;

import static org.junit.Assert.assertTrue;

import me.gv7.woodpecker.plugin.utils.CasCommonUtils;
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
    public void shouldAnswerWithTrue() {
        String urldns = CasCommonUtils.generate("URLDNS", "http://xxx.dnslog.cn");
        System.out.println(urldns);
    }
}
