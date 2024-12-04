package com.kimtr.web.jsonAPI;

import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.net.URL;
import java.util.Locale;

import javax.net.ssl.HttpsURLConnection;

import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class JsonAPI_top10 {

	
	@GetMapping(value = "/top10/js")
	public String top10(Locale locale, Model modele) throws Exception{
		System.out.println("kkk 한글");
		StringBuffer result = new StringBuffer();
		String line="";
		
		try {
			StringBuilder urlBuilder = new StringBuilder("https://www.nate.com/js/data/jsonLiveKeywordDataV1.js");
//			urlBuilder.append("&type=json");
			
			URL url = new URL(urlBuilder.toString());
			HttpsURLConnection conn = (HttpsURLConnection)url.openConnection();
			conn.setRequestMethod("GET");
			BufferedReader rd;
			
		//	if(conn.getResponseCode() >= 200 && conn.getResponseCode() <= 300) {
				rd = new BufferedReader(new InputStreamReader(conn.getInputStream(),"EUC-KR"));
		//	}else {
			//	rd = new BufferedReader(new InputStreamReader(conn.getInputStream()));
		//	}
			
			line = rd.readLine();
		//	while((line = rd.readLine())!= null) {
		//	System.out.println(">"+line);
		//	}
		//	System.out.println(line.length());
			// 문자열 분석 다양한 알고리즘
			
//			HashMap<String, String> top10List = new HashMap<String, String>();
//			for(int i=1; i<line.length(); i++) {
//				int endPoint = line.indexOf("]",i);
//				//System.out.println(i+"/"+endPoint +" 끝점");
//				System.out.println(line.substring(i+1,endPoint));
//				String cutWord = line.substring(i,endPoint+1);
//				String[] cutWordArray = cutWord.split(",");
//				top10List.put(cutWordArray[0].trim(), cutWordArray[1].trim());
//				int nextStart = line.indexOf("[",endPoint);
//				if(nextStart != -1) {
//					i=nextStart-1;
//				}else {
//					break;
//				}
//			//	System.out.println("바뀐 i 값 : "+i);
//			}	
//			System.out.println(top10List);
			rd.close();
			conn.disconnect();
		} catch (Exception e) {
			// TODO: handle exception
		}
		return line;  // 수정예정
	}
	
	
/*	@ResponseBody
	@RequestMapping(value = "/top10/js", method = RequestMethod.GET)
	public MemberVO top10(Locale locale, Model modele) throws Exception{
			System.out.println("top10js");
			MemberVO m = new MemberVO();
			m.setId("testid");
			m.setName("testname");
			m.setPoint(30);
		return m;  // 수정예정
	}*/
}
