package com.kimtr.web.repository;

import org.apache.ibatis.annotations.Mapper;

import com.kimtr.web.vo.MemberVO;

@Mapper
public interface IF_MemberDao {
	//디비 작업을 메서드로 정의 합니다.
	public void insertOne(MemberVO membervo)throws Exception;
	public MemberVO selectOne(String id) throws Exception;

}
/**
 * spring boot로 프로젝트를 생성, Mybatis 연동하는 예제입니다.
스프링에서 mybatis를 사용하는 방식은 SqlSession, SqlSessionTemplate을 설정하고
selectOne(maper네임스페이스.id, parameter) 등의 메서드를 통해 쿼리를 사용하였지만.
스프링부트, mybatis 3.0이상에서는 sqlSessionTemplate을 설정하고, selectone 메서드를 사용하지 않고,
복잡한 ~~~context.xml파일이 없어도
@mapper 어노테이션을 이용해 메서드명과 xml 파일의 id를 매핑시켜 편리하게 사용 할 수 있습니다.
 */
