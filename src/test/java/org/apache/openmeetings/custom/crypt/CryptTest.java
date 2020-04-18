package org.apache.openmeetings.custom.crypt;

import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.ArrayList;
import java.util.List;
import java.util.Random;

import org.apache.commons.text.RandomStringGenerator;
import org.apache.openmeetings.util.crypt.ICrypt;
import org.junit.jupiter.api.Test;

public class CryptTest {
	private static List<String> get(int count) {
		Random rnd = new Random();
		List<String> l = new ArrayList<>(count + 1);
		l.add("");
		RandomStringGenerator generator = new RandomStringGenerator.Builder()
				.withinRange('!', '}')
				.usingRandom(rnd::nextInt)
				.build();
		for (int i = 0; i < count; ++i) {
			l.add(generator.generate(rnd.nextInt(256)));
		}
		return l;
	}

	@Test
	public void test() {
		ICrypt crypt = new MyCustomCrypt();
		for (String str : get(64)) {
			String h1 = crypt.hash(str);
			assertNotNull(h1, "Hash should not be null");
			String h2 = crypt.hash(str);
			assertNotEquals(h1,  h2, "Hashes of same string should NOT be the same");
			assertTrue(crypt.verify(str, h1), "String should be verified successfully");
			assertTrue(crypt.verify(str, h2), "String should be verified successfully");
		}
	}

}
