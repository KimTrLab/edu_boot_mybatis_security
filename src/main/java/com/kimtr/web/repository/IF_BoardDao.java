package com.kimtr.web.repository;

import java.util.List;

import com.kimtr.web.vo.BoardVO;
import com.kimtr.web.vo.Pagevo;

public interface IF_BoardDao {
	// 디비작업이 목적
	// mybatis mapper랑 매핑해서 DB작업을 수행
	public void insertBoard(BoardVO boardvo)throws Exception;
	public List<BoardVO> selectAll(Pagevo pagevo) throws Exception;
	public void deleteBoard(String delno)throws Exception;
	public BoardVO selectOne(String title)throws Exception;
	public void updateBoard(BoardVO boardvo)throws Exception;
	public int cntBoard(Pagevo pagevo)throws Exception;
	public void insertAttach(String fname)throws Exception;
	public List<String> selectAllAttach(String no)throws Exception;
}

/**
 * spring boot로 프로젝트를 생성, Mybatis 연동하는 예제입니다.
스프링에서 mybatis를 사용하는 방식은 SqlSession, SqlSessionTemplate을 설정하고
selectOne(maper네임스페이스.id, parameter) 등의 메서드를 통해 쿼리를 사용하였지만.
스프링부트, mybatis 3.0이상에서는 sqlSessionTemplate을 설정하고, selectone 메서드를 사용하지 않고,
복잡한 ~~~context.xml파일이 없어도
@mapper 어노테이션을 이용해 메서드명과 xml 파일의 id를 매핑시켜 편리하게 사용 할 수 있습니다.
 */


