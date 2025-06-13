package com.example.courseworkLuchnetskyi.mapper;

import com.example.courseworkLuchnetskyi.dto.request.TournamentRequestDto;
import com.example.courseworkLuchnetskyi.dto.response.TournamentResponseDto;
import com.example.courseworkLuchnetskyi.model.Tournament;
import java.time.LocalDate;
import javax.annotation.processing.Generated;
import org.springframework.stereotype.Component;

@Generated(
    value = "org.mapstruct.ap.MappingProcessor",
    date = "2025-06-12T13:09:29+0300",
    comments = "version: 1.5.5.Final, compiler: javac, environment: Java 17.0.13 (Amazon.com Inc.)"
)
@Component
public class TournamentMapperImpl implements TournamentMapper {

    @Override
    public Tournament toEntity(TournamentRequestDto request) {
        if ( request == null ) {
            return null;
        }

        Tournament tournament = new Tournament();

        tournament.setName( request.name() );
        tournament.setStartDate( request.startDate() );
        tournament.setEndDate( request.endDate() );
        tournament.setLocation( request.location() );

        return tournament;
    }

    @Override
    public TournamentResponseDto toDto(Tournament tournament) {
        if ( tournament == null ) {
            return null;
        }

        Long id = null;
        String name = null;
        LocalDate startDate = null;
        LocalDate endDate = null;
        String location = null;

        id = tournament.getId();
        name = tournament.getName();
        startDate = tournament.getStartDate();
        endDate = tournament.getEndDate();
        location = tournament.getLocation();

        TournamentResponseDto tournamentResponseDto = new TournamentResponseDto( id, name, startDate, endDate, location );

        return tournamentResponseDto;
    }

    @Override
    public void updateTournamentFromRequest(Tournament tournament, TournamentRequestDto request) {
        if ( request == null ) {
            return;
        }

        if ( request.name() != null ) {
            tournament.setName( request.name() );
        }
        if ( request.startDate() != null ) {
            tournament.setStartDate( request.startDate() );
        }
        if ( request.endDate() != null ) {
            tournament.setEndDate( request.endDate() );
        }
        if ( request.location() != null ) {
            tournament.setLocation( request.location() );
        }
    }
}
