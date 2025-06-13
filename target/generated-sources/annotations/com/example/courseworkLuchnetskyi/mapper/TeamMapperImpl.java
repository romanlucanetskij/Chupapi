package com.example.courseworkLuchnetskyi.mapper;

import com.example.courseworkLuchnetskyi.dto.request.TeamRequestDto;
import com.example.courseworkLuchnetskyi.dto.response.TeamResponseDto;
import com.example.courseworkLuchnetskyi.model.Team;
import javax.annotation.processing.Generated;
import org.springframework.stereotype.Component;

@Generated(
    value = "org.mapstruct.ap.MappingProcessor",
    date = "2025-06-12T13:09:29+0300",
    comments = "version: 1.5.5.Final, compiler: javac, environment: Java 17.0.13 (Amazon.com Inc.)"
)
@Component
public class TeamMapperImpl implements TeamMapper {

    @Override
    public Team toEntity(TeamRequestDto dto) {
        if ( dto == null ) {
            return null;
        }

        Team team = new Team();

        team.setName( dto.name() );
        team.setCity( dto.city() );

        return team;
    }

    @Override
    public TeamResponseDto toDto(Team team) {
        if ( team == null ) {
            return null;
        }

        Long id = null;
        String name = null;
        String city = null;

        id = team.getId();
        name = team.getName();
        city = team.getCity();

        TeamResponseDto teamResponseDto = new TeamResponseDto( id, name, city );

        return teamResponseDto;
    }

    @Override
    public void updateTeamFromDto(Team team, TeamRequestDto dto) {
        if ( dto == null ) {
            return;
        }

        if ( dto.name() != null ) {
            team.setName( dto.name() );
        }
        if ( dto.city() != null ) {
            team.setCity( dto.city() );
        }
    }
}
